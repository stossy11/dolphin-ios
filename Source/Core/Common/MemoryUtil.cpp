// Copyright 2008 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "Common/MemoryUtil.h"

#include <cstddef>
#include <cstdlib>
#include <string>

#include "Common/CommonFuncs.h"
#include "Common/CommonTypes.h"
#include "Common/Logging/Log.h"
#include "Common/MsgHandler.h"

#ifdef _WIN32
#include <windows.h>
#include "Common/StringUtil.h"
#else
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#if defined __APPLE__ || defined __FreeBSD__ || defined __OpenBSD__ || defined __NetBSD__
#include <sys/sysctl.h>
#elif defined __HAIKU__
#include <OS.h>
#else
#include <sys/sysinfo.h>
#endif
#endif

#ifdef IPHONEOS
#include "Common/JITMemoryTracker.h"
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <unordered_map>
#endif

namespace Common
{
// This is purposely not a full wrapper for virtualalloc/mmap, but it
// provides exactly the primitive operations that Dolphin needs.

#ifdef IPHONEOS
static JITMemoryTracker g_jit_memory_tracker;
#endif

#ifdef IPHONEOS
// iOS-specific dual mapping structure
struct IOSJITRegion {
    void* rw_ptr;     // Read-write mapping
    void* rx_ptr;     // Read-execute mapping
    size_t size;
    vm_address_t rw_addr;
    vm_address_t rx_addr;
};

static std::unordered_map<void*, IOSJITRegion> g_ios_jit_regions;

void* AllocateExecutableMemory(size_t size)
{
    // Create initial RW mapping
    void* rw_ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (rw_ptr == MAP_FAILED) {
        PanicAlertFmt("Failed to allocate RW memory for iOS JIT: {}", LastStrerrorString());
        return nullptr;
    }

    vm_address_t rw_addr = vm_address_t(reinterpret_cast<uintptr_t>(rw_ptr));
    vm_address_t rx_addr = 0;
    vm_prot_t cur_prot = 0;
    vm_prot_t max_prot = 0;

    // Create RX mapping via vm_remap
    kern_return_t remap_result = vm_remap(
        mach_task_self(),
        &rx_addr,
        vm_size_t(size),
        0,
        VM_FLAGS_ANYWHERE,
        mach_task_self(),
        rw_addr,
        0,
        &cur_prot,
        &max_prot,
        VM_INHERIT_NONE
    );

    if (remap_result != KERN_SUCCESS) {
        munmap(rw_ptr, size);
        PanicAlertFmt("Failed to remap RX region for iOS JIT: {}", remap_result);
        return nullptr;
    }

    // Set RX protection
    kern_return_t protect_rx = vm_protect(
        mach_task_self(),
        rx_addr,
        vm_size_t(size),
        0,
        VM_PROT_READ | VM_PROT_EXECUTE
    );

    if (protect_rx != KERN_SUCCESS) {
        munmap(rw_ptr, size);
        vm_deallocate(mach_task_self(), rx_addr, size);
        PanicAlertFmt("Failed to set RX protection for iOS JIT: {}", protect_rx);
        return nullptr;
    }

    // Set RW protection (should already be set, but ensure it)
    kern_return_t protect_rw = vm_protect(
        mach_task_self(),
        rw_addr,
        vm_size_t(size),
        0,
        VM_PROT_READ | VM_PROT_WRITE
    );

    if (protect_rw != KERN_SUCCESS) {
        munmap(rw_ptr, size);
        vm_deallocate(mach_task_self(), rx_addr, size);
        PanicAlertFmt("Failed to set RW protection for iOS JIT: {}", protect_rw);
        return nullptr;
    }

    void* rx_ptr = reinterpret_cast<void*>(rx_addr);
    
    // Store the mapping info
    IOSJITRegion region = {
        .rw_ptr = rw_ptr,
        .rx_ptr = rx_ptr,
        .size = size,
        .rw_addr = rw_addr,
        .rx_addr = rx_addr
    };
    
    g_ios_jit_regions[rx_ptr] = region;
    
    // Register with the JIT memory tracker using the RX pointer
    g_jit_memory_tracker.RegisterJITRegion(rx_ptr, size);

    return rx_ptr; // Return the executable pointer
}

void JITPageWriteEnableExecuteDisable(void* ptr)
{
    auto it = g_ios_jit_regions.find(ptr);
    if (it != g_ios_jit_regions.end()) {
        // For iOS, we don't need to change protections since we have separate RW/RX mappings
        // The JIT memory tracker will handle switching between the pointers
        g_jit_memory_tracker.JITRegionWriteEnableExecuteDisable(ptr);
    }
}

void JITPageWriteDisableExecuteEnable(void* ptr)
{
    auto it = g_ios_jit_regions.find(ptr);
    if (it != g_ios_jit_regions.end()) {
        g_jit_memory_tracker.JITRegionWriteDisableExecuteEnable(ptr);
    }
}

bool FreeMemoryPages(void* ptr, size_t size)
{
    if (ptr) {
        auto it = g_ios_jit_regions.find(ptr);
        if (it != g_ios_jit_regions.end()) {
            IOSJITRegion& region = it->second;
            
            // Unregister from JIT tracker first
            g_jit_memory_tracker.UnregisterJITRegion(ptr);
            
            // Free both mappings
            if (munmap(region.rw_ptr, region.size) != 0) {
                PanicAlertFmt("FreeMemoryPages failed to unmap RW region!\nmunmap: {}", LastStrerrorString());
                return false;
            }
            
            if (vm_deallocate(mach_task_self(), region.rx_addr, region.size) != KERN_SUCCESS) {
                PanicAlertFmt("FreeMemoryPages failed to deallocate RX region!");
                return false;
            }
            
            g_ios_jit_regions.erase(it);
            return true;
        }
        
        // Fallback to regular munmap if not found in our regions
        if (munmap(ptr, size) != 0) {
            PanicAlertFmt("FreeMemoryPages failed!\nmunmap: {}", LastStrerrorString());
            return false;
        }
    }
    return true;
}

// Helper function to get the RW pointer for a given RX pointer
void* GetWritablePointerForExecutable(void* rx_ptr)
{
    auto it = g_ios_jit_regions.find(rx_ptr);
    if (it != g_ios_jit_regions.end()) {
        return it->second.rw_ptr;
    }
    return nullptr;
}

#endif // IPHONEOS

#ifndef IPHONEOS
// This function is used to provide a counter for the JITPageWrite*Execute*
// functions to enable nesting. The static variable is wrapped in a a function
// to allow those functions to be called inside of the constructor of a static
// variable portably.
//
// The variable is thread_local as the W^X mode is specific to each running thread.
static int& JITPageWriteNestCounter()
{
  static thread_local int nest_counter = 0;
  return nest_counter;
}

// Certain platforms (Mac OS on ARM) enforce that a single thread can only have write or
// execute permissions to pages at any given point of time. The two below functions
// are used to toggle between having write permissions or execute permissions.
//
// The default state of these allocations in Dolphin is for them to be executable,
// but not writeable. So, functions that are updating these pages should wrap their
// writes like below:

// JITPageWriteEnableExecuteDisable();
// PrepareInstructionStreamForJIT();
// JITPageWriteDisableExecuteEnable();

// These functions can be nested, in which case execution will only be enabled
// after the call to the JITPageWriteDisableExecuteEnable from the top most
// nesting level. Example:

// [JIT page is in execute mode for the thread]
// JITPageWriteEnableExecuteDisable();
//   [JIT page is in write mode for the thread]
//   JITPageWriteEnableExecuteDisable();
//     [JIT page is in write mode for the thread]
//   JITPageWriteDisableExecuteEnable();
//   [JIT page is in write mode for the thread]
// JITPageWriteDisableExecuteEnable();
// [JIT page is in execute mode for the thread]

// Allows a thread to write to executable memory, but not execute the data.
void JITPageWriteEnableExecuteDisable()
{
#if defined(_M_ARM_64) && defined(__APPLE__) && !defined(IPHONEOS)
  if (JITPageWriteNestCounter() == 0)
  {
    if (__builtin_available(macOS 11.0, *))
    {
      pthread_jit_write_protect_np(0);
    }
  }
#endif
  JITPageWriteNestCounter()++;
}
// Allows a thread to execute memory allocated for execution, but not write to it.
void JITPageWriteDisableExecuteEnable()
{
  JITPageWriteNestCounter()--;

  // Sanity check the NestCounter to identify underflow
  // This can indicate the calls to JITPageWriteDisableExecuteEnable()
  // are not matched with previous calls to JITPageWriteEnableExecuteDisable()
  if (JITPageWriteNestCounter() < 0)
    PanicAlertFmt("JITPageWriteNestCounter() underflowed");

#if defined(_M_ARM_64) && defined(__APPLE__) && !defined(IPHONEOS)
  if (JITPageWriteNestCounter() == 0)
  {
    if (__builtin_available(macOS 11.0, *))
    {
      pthread_jit_write_protect_np(1);
    }
  }
#endif
}
#else
// void JITPageWriteEnableExecuteDisable(void* ptr)
// {
  // g_jit_memory_tracker.JITRegionWriteEnableExecuteDisable(ptr);
// }

// void JITPageWriteDisableExecuteEnable(void* ptr)
// {
 //  g_jit_memory_tracker.JITRegionWriteDisableExecuteEnable(ptr);
// }
#endif

void* AllocateMemoryPages(size_t size)
{
#ifdef _WIN32
  void* ptr = VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_READWRITE);
#else
  void* ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

  if (ptr == MAP_FAILED)
    ptr = nullptr;
#endif

  if (ptr == nullptr)
    PanicAlertFmt("Failed to allocate raw memory");

  return ptr;
}

void* AllocateAlignedMemory(size_t size, size_t alignment)
{
#ifdef _WIN32
  void* ptr = _aligned_malloc(size, alignment);
#else
  void* ptr = nullptr;
  if (posix_memalign(&ptr, alignment, size) != 0)
    ERROR_LOG_FMT(MEMMAP, "Failed to allocate aligned memory");
#endif

  if (ptr == nullptr)
    PanicAlertFmt("Failed to allocate aligned memory");

  return ptr;
}

bool FreeMemoryPages2(void* ptr, size_t size)
{
  if (ptr)
  {
#ifdef _WIN32
    if (!VirtualFree(ptr, 0, MEM_RELEASE))
    {
      PanicAlertFmt("FreeMemoryPages failed!\nVirtualFree: {}", GetLastErrorString());
      return false;
    }
#else
    if (munmap(ptr, size) != 0)
    {
      PanicAlertFmt("FreeMemoryPages failed!\nmunmap: {}", LastStrerrorString());
      return false;
    }
#endif

#ifdef IPHONEOS
    g_jit_memory_tracker.UnregisterJITRegion(ptr);
#endif
  }
  return true;
}

void FreeAlignedMemory(void* ptr)
{
  if (ptr)
  {
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
  }
}

bool ReadProtectMemory(void* ptr, size_t size)
{
#ifdef _WIN32
  DWORD oldValue;
  if (!VirtualProtect(ptr, size, PAGE_NOACCESS, &oldValue))
  {
    PanicAlertFmt("ReadProtectMemory failed!\nVirtualProtect: {}", GetLastErrorString());
    return false;
  }
#else
  if (mprotect(ptr, size, PROT_NONE) != 0)
  {
    PanicAlertFmt("ReadProtectMemory failed!\nmprotect: {}", LastStrerrorString());
    return false;
  }
#endif
  return true;
}

bool WriteProtectMemory(void* ptr, size_t size, bool allowExecute)
{
#ifdef _WIN32
  DWORD oldValue;
  if (!VirtualProtect(ptr, size, allowExecute ? PAGE_EXECUTE_READ : PAGE_READONLY, &oldValue))
  {
    PanicAlertFmt("WriteProtectMemory failed!\nVirtualProtect: {}", GetLastErrorString());
    return false;
  }
#elif !(defined(_M_ARM_64) && defined(__APPLE__) && !defined(IPHONEOS))
  // MacOS 11.2 on ARM does not allow for changing the access permissions of pages
  // that were marked executable, instead it uses the protections offered by MAP_JIT
  // for write protection.
  if (mprotect(ptr, size, allowExecute ? (PROT_READ | PROT_EXEC) : PROT_READ) != 0)
  {
    PanicAlertFmt("WriteProtectMemory failed!\nmprotect: {}", LastStrerrorString());
    return false;
  }
#endif
  return true;
}

bool UnWriteProtectMemory(void* ptr, size_t size, bool allowExecute)
{
#ifdef _WIN32
  DWORD oldValue;
  if (!VirtualProtect(ptr, size, allowExecute ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &oldValue))
  {
    PanicAlertFmt("UnWriteProtectMemory failed!\nVirtualProtect: {}", GetLastErrorString());
    return false;
  }
#elif !(defined(_M_ARM_64) && defined(__APPLE__) && !defined(IPHONEOS))
  // MacOS 11.2 on ARM does not allow for changing the access permissions of pages
  // that were marked executable, instead it uses the protections offered by MAP_JIT
  // for write protection.
  if (mprotect(ptr, size,
               allowExecute ? (PROT_READ | PROT_WRITE | PROT_EXEC) : PROT_WRITE | PROT_READ) != 0)
  {
    PanicAlertFmt("UnWriteProtectMemory failed!\nmprotect: {}", LastStrerrorString());
    return false;
  }
#endif
  return true;
}

size_t MemPhysical()
{
#ifdef _WIN32
  MEMORYSTATUSEX memInfo;
  memInfo.dwLength = sizeof(MEMORYSTATUSEX);
  GlobalMemoryStatusEx(&memInfo);
  return memInfo.ullTotalPhys;
#elif defined __APPLE__ || defined __FreeBSD__ || defined __OpenBSD__ || defined __NetBSD__
  int mib[2];
  size_t physical_memory;
  mib[0] = CTL_HW;
#ifdef __APPLE__
  mib[1] = HW_MEMSIZE;
#elif defined __FreeBSD__
  mib[1] = HW_REALMEM;
#elif defined __OpenBSD__ || defined __NetBSD__
  mib[1] = HW_PHYSMEM64;
#endif
  size_t length = sizeof(size_t);
  sysctl(mib, 2, &physical_memory, &length, nullptr, 0);
  return physical_memory;
#elif defined __HAIKU__
  system_info sysinfo;
  get_system_info(&sysinfo);
  return static_cast<size_t>(sysinfo.max_pages * B_PAGE_SIZE);
#else
  struct sysinfo memInfo;
  sysinfo(&memInfo);
  return (size_t)memInfo.totalram * memInfo.mem_unit;
#endif
}

}  // namespace Common
