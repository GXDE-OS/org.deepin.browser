// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/gpu/gpu_mode_manager.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/user_metrics.h"
#include "chrome/browser/browser_process.h"
#include "chrome/common/pref_names.h"
#include "components/prefs/pref_registry_simple.h"
#include "components/prefs/pref_service.h"
#include "content/public/browser/gpu_data_manager.h"

using base::UserMetricsAction;

namespace {

bool GetPreviousGpuModePref() {
  LOG(INFO)<<"GetPreviousGpuModePref";
  PrefService* service = g_browser_process->local_state();
  DCHECK(service);
  return service->GetBoolean(prefs::kHardwareAccelerationModePrevious);
}

void SetPreviousGpuModePref(bool enabled) {
  LOG(INFO)<<"SetPreviousGpuModePref";
  PrefService* service = g_browser_process->local_state();
  DCHECK(service);
  service->SetBoolean(prefs::kHardwareAccelerationModePrevious, enabled);
}

bool GetPreviousVideoDecodeModePref() {
  LOG(INFO)<<"GetPreviousVideoDecodeModePref";
  PrefService* service = g_browser_process->local_state();
  DCHECK(service);
  return service->GetBoolean(prefs::kVideoDecodeAccelerationModePrevious);
}

void SetPreviousVideoDecodeModePref(bool enabled) {
  LOG(INFO)<<"SetPreviousVideoDecodeModePref";
  PrefService* service = g_browser_process->local_state();
  DCHECK(service);
  service->SetBoolean(prefs::kVideoDecodeAccelerationModePrevious, enabled);
}

}  // namespace

// static
void GpuModeManager::RegisterPrefs(PrefRegistrySimple* registry) {
  registry->RegisterBooleanPref(
      prefs::kHardwareAccelerationModeEnabled, true);
  registry->RegisterBooleanPref(
      prefs::kHardwareAccelerationModePrevious, true);
  registry->RegisterBooleanPref(
      prefs::kVideoDecodeAccelerationModeEnabled, false);
  registry->RegisterBooleanPref(
      prefs::kVideoDecodeAccelerationModeEnabled, false);
}

GpuModeManager::GpuModeManager()
    : initial_gpu_mode_pref_(true)
    , initial_video_decode_mode_pref_ (false) {
  if (g_browser_process->local_state()) {  // Skip for unit tests
    pref_registrar_.Init(g_browser_process->local_state());
    // Do nothing when the pref changes. It takes effect after
    // chrome restarts.
    pref_registrar_.Add(prefs::kHardwareAccelerationModeEnabled,
                        base::DoNothing::Repeatedly<>());
    pref_registrar_.Add(prefs::kVideoDecodeAccelerationModeEnabled,
                        base::DoNothing::Repeatedly<>());

    initial_gpu_mode_pref_ = IsGpuModePrefEnabled();
    bool previous_gpu_mode_pref = GetPreviousGpuModePref();
    SetPreviousGpuModePref(initial_gpu_mode_pref_);

    initial_video_decode_mode_pref_ = IsVideoDecodeModePrefEnabled();
    bool previous_video_decode_mode_pref = GetPreviousVideoDecodeModePref();
    SetPreviousVideoDecodeModePref(initial_video_decode_mode_pref_);

    UMA_HISTOGRAM_BOOLEAN("GPU.HardwareAccelerationModeEnabled",
                          initial_gpu_mode_pref_);
    if (previous_gpu_mode_pref && !initial_gpu_mode_pref_)
      base::RecordAction(UserMetricsAction("GpuAccelerationDisabled"));
    if (!previous_gpu_mode_pref && initial_gpu_mode_pref_)
      base::RecordAction(UserMetricsAction("GpuAccelerationEnabled"));

    UMA_HISTOGRAM_BOOLEAN("GPU.VideoDecodeAccelerationModeEnabled",
                          initial_video_decode_mode_pref_);
    if (previous_video_decode_mode_pref && !initial_video_decode_mode_pref_)
      base::RecordAction(UserMetricsAction("VideoDecodeAccelerationEnabled"));
    if (!previous_video_decode_mode_pref && initial_video_decode_mode_pref_)
      base::RecordAction(UserMetricsAction("VideoDecodeAccelerationDisabled"));

    if (!initial_gpu_mode_pref_) {
      content::GpuDataManager* gpu_data_manager =
          content::GpuDataManager::GetInstance();
      DCHECK(gpu_data_manager);
      gpu_data_manager->DisableHardwareAcceleration();
    }

    if (content::GpuDataManager::GetInstance()) {
      content::GpuDataManager::GetInstance()->SetVideoDecodeAcceleration(initial_video_decode_mode_pref_);
    }
  }
}

GpuModeManager::~GpuModeManager() {
}

bool GpuModeManager::initial_gpu_mode_pref() const {
  LOG(INFO)<<"initial_gpu_mode_pref:"<<initial_gpu_mode_pref_;
  return initial_gpu_mode_pref_;
}

bool GpuModeManager::initial_video_decode_mode_pref() const {
  LOG(INFO)<<"initial_gpu_mode_pref:"<<initial_video_decode_mode_pref_;
  return initial_video_decode_mode_pref_;
}

// static
bool GpuModeManager::IsGpuModePrefEnabled() {
  LOG(INFO)<<"IsGpuModePrefEnabled:";

  PrefService* service = g_browser_process->local_state();
  DCHECK(service);
  return service->GetBoolean(
      prefs::kHardwareAccelerationModeEnabled);
}

// static
bool GpuModeManager::IsVideoDecodeModePrefEnabled() {
  LOG(INFO)<<"IsVideoDecodeModePrefEnabled:";

  PrefService* service = g_browser_process->local_state();
  DCHECK(service);
  return service->GetBoolean(
      prefs::kVideoDecodeAccelerationModeEnabled);
}

