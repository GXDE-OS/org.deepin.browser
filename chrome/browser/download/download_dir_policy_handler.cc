// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/download/download_dir_policy_handler.h"

#include <stddef.h>

#include <memory>

#include "base/files/file_path.h"
#include "base/values.h"
#include "build/build_config.h"
#include "chrome/browser/download/download_dir_util.h"
#include "chrome/browser/download/download_prefs.h"
#include "chrome/browser/policy/policy_path_parser.h"
#include "chrome/common/pref_names.h"
#include "components/drive/drive_pref_names.h"
#include "components/policy/core/browser/configuration_policy_handler_parameters.h"
#include "components/policy/core/browser/policy_error_map.h"
#include "components/policy/core/common/policy_map.h"
#include "components/policy/core/common/policy_types.h"
#include "components/policy/policy_constants.h"
#include "components/prefs/pref_value_map.h"
#include "components/strings/grit/components_strings.h"

DownloadDirPolicyHandler::DownloadDirPolicyHandler()
    : TypeCheckingPolicyHandler(policy::key::kDownloadDirectory,
                                base::Value::Type::STRING) {}

DownloadDirPolicyHandler::~DownloadDirPolicyHandler() {}

bool DownloadDirPolicyHandler::CheckPolicySettings(
    const policy::PolicyMap& policies,
    policy::PolicyErrorMap* errors) {
  const base::Value* value = NULL;
  if (!CheckAndGetValue(policies, errors, &value))
    return false;

#if defined(OS_CHROMEOS)
  // Download directory can only be set as a user policy. If it is set through
  // platform policy for a chromeos=1 build, ignore it.
  if (value &&
      policies.Get(policy_name())->scope != policy::POLICY_SCOPE_USER) {
    errors->AddError(policy_name(), IDS_POLICY_SCOPE_ERROR);
    return false;
  }
#endif

  return true;
}

void DownloadDirPolicyHandler::ApplyPolicySettingsWithParameters(
    const policy::PolicyMap& policies,
    const policy::PolicyHandlerParameters& parameters,
    PrefValueMap* prefs) {
  const base::Value* value = policies.GetValue(policy_name());
  base::FilePath::StringType string_value;
  if (!value || !value->GetAsString(&string_value))
    return;

  // Make sure the path isn't empty, since that will point to an undefined
  // location; the default location is used instead in that case.
  // This is checked after path expansion because a non-empty policy value can
  // lead to an empty path value after expansion (e.g. "\"\"").
  base::FilePath::StringType expanded_value =
      download_dir_util::ExpandDownloadDirectoryPath(string_value, parameters);
  if (expanded_value.empty()) {
    expanded_value = policy::path_parser::ExpandPathVariables(
        DownloadPrefs::GetDefaultDownloadDirectory().value());
  }
  prefs->SetValue(prefs::kDownloadDefaultDirectory,
                  base::Value(expanded_value));
#ifndef OPENSSL_NO_GMTLS
  prefs->SetValue(prefs::kUsbKeyDirectory,
                  base::Value(expanded_value));
#endif
  // If the policy is mandatory, prompt for download should be disabled.
  // Otherwise, it would enable a user to bypass the mandatory policy.
  if (policies.Get(policy_name())->level == policy::POLICY_LEVEL_MANDATORY) {
    LOG(INFO)<<"prefs::kPromptForDownload:"<<false;
    prefs->SetBoolean(prefs::kPromptForDownload, false);
#if defined(OS_CHROMEOS)
    if (download_dir_util::DownloadToDrive(string_value, parameters)) {
      prefs->SetBoolean(drive::prefs::kDisableDrive, false);
    }
#endif
  }
}

void DownloadDirPolicyHandler::ApplyPolicySettings(
    const policy::PolicyMap& /* policies */,
    PrefValueMap* /* prefs */) {
  NOTREACHED();
}
