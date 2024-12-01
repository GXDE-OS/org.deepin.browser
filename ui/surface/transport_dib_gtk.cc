// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ui/surface/transport_dib.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "third_party/skia/include/core/SkImageInfo.h"
// Desktop GTK Linux builds use the old-style SYSV SHM based DIBs.

#include <errno.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "skia/ext/platform_canvas.h"
#include "ui/gfx/geometry/size.h"

// The shmat system call uses this as it's invalid return address
static void *const kInvalidAddress = (void*) -1;

TransportDIB::TransportDIB()
    : address_(kInvalidAddress),
      x_shm_(0),
      display_(NULL),
      inflight_counter_(0),
      detached_(false),
      size_(0) {
}

TransportDIB::~TransportDIB() {
  if (!shm_region_.IsValid()) {
    LOG(INFO) << "[NPAPI][GTK] Deconstruct TransportDIB";
    if (address_ != kInvalidAddress) {
      shmdt(address_);
      address_ = kInvalidAddress;
    }

    if (x_shm_) {
      DCHECK(display_);
      ui::DetachSharedMemory(display_, x_shm_);
    }
  }
}

// static
TransportDIB* TransportDIB::Create(size_t size, uint32_t sequence_num) {
  const int shmkey = shmget(IPC_PRIVATE, size, 0600);
  if (shmkey == -1) {
    LOG(ERROR) << "Failed to create SysV shared memory region"
                << " errno:" << errno;
    return NULL;
  } else {
    LOG(INFO) << "Created SysV shared memory region " << shmkey;
  }

  void* address = shmat(shmkey, NULL /* desired address */, 0 /* flags */);
  // Here we mark the shared memory for deletion. Since we attached it in the
  // line above, it doesn't actually get deleted but, if we crash, this means
  // that the kernel will automatically clean it up for us.
  shmctl(shmkey, IPC_RMID, 0);
  if (address == kInvalidAddress)
    return NULL;

  TransportDIB* dib = new TransportDIB;

  dib->key_.shmkey = shmkey;
  dib->address_ = address;
  dib->size_ = size;
  return dib;
}

// static
std::unique_ptr<TransportDIB> TransportDIB::Map(Handle handle) {
  std::unique_ptr<TransportDIB> dib = CreateWithHandle(handle);
  if (!dib->MapGTK())
    return NULL;
  return dib;
}

// static
std::unique_ptr<TransportDIB> TransportDIB::CreateWithHandle(Handle shmkey) {
  TransportDIB* dib = new TransportDIB;
  dib->key_.shmkey = shmkey;
  return base::WrapUnique(dib);
}

// static
bool TransportDIB::is_valid_handle(Handle dib) {
  return dib >= 0;
}

// static
bool TransportDIB::is_valid_id(Id id) {
  return id.shmkey != -1;
}

std::unique_ptr<SkCanvas> TransportDIB::GetPlatformCanvasGTK(int w, int h) {
  if ((address_ == kInvalidAddress && !MapGTK()) || !VerifyCanvasSize(w, h))
    return NULL;
  return skia::CreatePlatformCanvasWithPixels(w, h, true,
                                    reinterpret_cast<uint8_t*>(memoryGTK()),
                                    skia::RETURN_NULL_ON_FAILURE);
}


std::unique_ptr<SkBitmap> TransportDIB::GetPlatformCanvasGTK(int w, int h, bool opaque){

  std::unique_ptr<SkBitmap> bitmap = std::make_unique<SkBitmap>();
  bitmap->setInfo(SkImageInfo::MakeN32(w,h, opaque ? kOpaque_SkAlphaType : kPremul_SkAlphaType));

  if(memoryGTK()){
      bitmap->setPixels(reinterpret_cast<uint8_t*>(memoryGTK()));
  }else{
      if(!bitmap->tryAllocPixels()){
          return nullptr;
      }
      if(!opaque)
          bitmap->eraseARGB(0,0,0,0);
  }
  return bitmap;
}
bool TransportDIB::MapGTK() {
  if (!is_valid_id(key_))
    return false;
  if (address_ != kInvalidAddress)
    return true;

  struct shmid_ds shmst;
  if (shmctl(key_.shmkey, IPC_STAT, &shmst) == -1)
    return false;

  void* address = shmat(key_.shmkey, NULL /* desired address */, 0 /* flags */);
  if (address == kInvalidAddress)
    return false;

  address_ = address;
  size_ = shmst.shm_segsz;
  return true;
}

void* TransportDIB::memoryGTK() const {
  DCHECK_NE(address_, kInvalidAddress);
  return address_;
}

TransportDIB::Id TransportDIB::id() const {
  return key_;
}

TransportDIB::Handle TransportDIB::handle() const {
  return key_.shmkey;
}

XID TransportDIB::MapToX(XDisplay* display) {
  if (!x_shm_) {
    x_shm_ = ui::AttachSharedMemory(display, key_.shmkey);
    display_ = display;
  }

  return x_shm_;
}

void TransportDIB::DecreaseInFlightCounter() {
  CHECK(inflight_counter_);
  inflight_counter_--;
  if (!inflight_counter_ && detached_)
    delete this;
}

void TransportDIB::Detach() {
  CHECK(!detached_);
  detached_ = true;
  if (!inflight_counter_)
    delete this;
}

