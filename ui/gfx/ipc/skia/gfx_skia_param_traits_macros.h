// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UI_GFX_IPC_SKIA_GFX_SKIA_PARAM_TRAITS_MACROS_H_
#define UI_GFX_IPC_SKIA_GFX_SKIA_PARAM_TRAITS_MACROS_H_

#include <stdint.h>

#include "ipc/ipc_message_macros.h"
#include "third_party/skia/include/core/SkImageInfo.h"

IPC_ENUM_TRAITS_VALIDATE(SkColorType, value != kLastEnum_SkColorType)
IPC_ENUM_TRAITS_VALIDATE(SkAlphaType, value != kLastEnum_SkAlphaType)

#endif  // UI_GFX_IPC_SKIA_GFX_SKIA_PARAM_TRAITS_MACROS_H_
