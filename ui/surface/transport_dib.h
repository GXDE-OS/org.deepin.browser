// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UI_SURFACE_TRANSPORT_DIB_H_
#define UI_SURFACE_TRANSPORT_DIB_H_

#include <stddef.h>
#include <memory>

#include "base/macros.h"
#include "base/memory/shared_memory_mapping.h"
#include "base/memory/unsafe_shared_memory_region.h"
#include "ui/base/buildflags.h"
#include "ui/surface/surface_export.h"
#include "ui/base/x/x11_util.h"
#include "ui/gfx/x/x11_types.h"

class SkCanvas;

// -----------------------------------------------------------------------------
// A TransportDIB is a block of memory that is used to transport pixels
// between processes: from the renderer process to the browser, and
// between renderer and plugin processes.
// -----------------------------------------------------------------------------
class SURFACE_EXPORT TransportDIB {
 public:
  ~TransportDIB();

  typedef int Handle;  // These two ints are SysV IPC shared memory keys
  struct Id {
    // Ensure that default initialized Ids are invalid.
    Id() : shmkey(-1) {
    }

    bool operator<(const Id& other) const {
      return shmkey < other.shmkey;
    }

    bool operator==(const Id& other) const {
      return shmkey == other.shmkey;
    }

    int shmkey;
  };

  // Returns a default, invalid handle, that is meant to indicate a missing
  // Transport DIB.
  static Handle DefaultHandleValue() { return -1; }

  // Creates and maps a new TransportDIB with a shared memory region.
  // Returns nullptr on failure.
  static std::unique_ptr<TransportDIB> Map(
      base::UnsafeSharedMemoryRegion region);

  // Creates a new TransportDIB with a shared memory region. This always returns
  // a valid pointer. The DIB is not mapped.
  static std::unique_ptr<TransportDIB> CreateWithHandle(
      base::UnsafeSharedMemoryRegion region);

  static TransportDIB* Create(size_t size, uint32_t sequence_num);

  // Map the referenced transport DIB.  The caller owns the returned object.
  // Returns NULL on failure.
  static std::unique_ptr<TransportDIB> Map(Handle transport_dib);

  // Create a new |TransportDIB| with a handle to the shared memory. This
  // always returns a valid pointer. The DIB is not mapped.
  static std::unique_ptr<TransportDIB> CreateWithHandle(Handle handle);

  // Returns true if the handle is valid.
  static bool is_valid_handle(Handle dib);

  // Returns true if the ID refers to a valid dib.
  static bool is_valid_id(Id id);

  // Returns a canvas using the memory of this TransportDIB. The returned
  // pointer will be owned by the caller. The bitmap will be of the given size,
  // which should fit inside this memory. Bitmaps returned will be either
  // opaque or have premultiplied alpha.
  //
  // On POSIX, this |TransportDIB| will be mapped if not already. On Windows,
  // this |TransportDIB| will NOT be mapped and should not be mapped prior,
  // because PlatformCanvas will map the file internally.
  //
  // Will return NULL on allocation failure. This could be because the image
  // is too large to map into the current process' address space.
  std::unique_ptr<SkCanvas> GetPlatformCanvas(int w, int h, bool opaque);
  std::unique_ptr<SkCanvas> GetPlatformCanvasGTK(int w, int h);
  std::unique_ptr<SkBitmap> GetPlatformCanvasGTK(int w, int h, bool opaque);

  // Map the DIB into the current process if it is not already. This is used to
  // map a DIB that has already been created. Returns true if the DIB is mapped.
  bool Map();
  bool MapGTK();

  // Return a pointer to the shared memory.
  void* memory() const;
  void* memoryGTK() const;

  // Return the maximum size of the shared memory. This is not the amount of
  // data which is valid, you have to know that via other means, this is simply
  // the maximum amount that /could/ be valid.
  size_t size() const { return size_; }

  // Returns a pointer to the UnsafeSharedMemoryRegion object that backs the
  // transport dib.
  base::UnsafeSharedMemoryRegion* shared_memory_region();

  // Return the identifier which can be used to refer to this shared memory
  // on the wire.
  Id id() const;

  // Return a handle to the underlying shared memory. This can be sent over the
  // wire to give this transport DIB to another process.
  Handle handle() const;

#if BUILDFLAG(USE_GTK)
  // Map the shared memory into the X server and return an id for the shared
  // segment.
  XID MapToX(XDisplay* connection);

  void IncreaseInFlightCounter() { inflight_counter_++; }
  // Decreases the inflight counter, and deletes the transport DIB if it is
  // detached.
  void DecreaseInFlightCounter();

  // Deletes this transport DIB and detaches the shared memory once the
  // |inflight_counter_| is zero.
  void Detach();
#endif

 private:
  TransportDIB();
  // Verifies that the dib can hold a canvas of the requested dimensions.
  bool VerifyCanvasSize(int w, int h);

  explicit TransportDIB(base::UnsafeSharedMemoryRegion region);

  base::UnsafeSharedMemoryRegion shm_region_;
  base::WritableSharedMemoryMapping shm_mapping_;
  size_t size_ = 0;

#if BUILDFLAG(USE_GTK)
  Id key_;  // SysV shared memory id
  void* address_;  // mapped address
  XSharedMemoryId x_shm_;  // X id for the shared segment
  XDisplay* display_;  // connection to the X server
  size_t inflight_counter_;  // How many requests to the X server are in flight
  bool detached_;  // If true, delete the transport DIB when it is idle
#endif

  DISALLOW_COPY_AND_ASSIGN(TransportDIB);
};

#endif  // UI_SURFACE_TRANSPORT_DIB_H_
