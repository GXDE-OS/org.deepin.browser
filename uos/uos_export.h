// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UOS_UOS_EXPORT_H_
#define UOS_UOS_EXPORT_H_

#if defined(COMPONENT_BUILD) && defined(WIN32)

#if defined(UOS_IMPLEMENTATION)
#define UOS_EXPORT __declspec(dllexport)
#else
#define UOS_EXPORT __declspec(dllimport)
#endif

#elif defined(COMPONENT_BUILD) && !defined(WIN32)

#if defined(UOS_IMPLEMENTATION)
#define UOS_EXPORT __attribute__((visibility("default")))
#else
#define UOS_EXPORT
#endif

#else
#define UOS_EXPORT
#endif

#endif  // DEVICE_BLUETOOTH_DEVICE_BLUETOOTH_EXPORT_H_
