// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/common/extensions/manifest_handlers/minimum_chrome_version_checker.h"

#include "base/strings/utf_string_conversions.h"
#include "base/version.h"
#include "base/no_destructor.h" //wangfeng: add header for extensions, 2020/08/14
#include "components/version_info/version_info_values.h" //wangfeng: add header for extensions, 2020/08/14
#include "chrome/grit/chromium_strings.h"
#include "components/version_info/version_info.h"
#include "extensions/common/error_utils.h"
#include "extensions/common/extension.h"
#include "extensions/common/manifest_constants.h"
#include "ui/base/l10n/l10n_util.h"

namespace extensions {

namespace keys = manifest_keys;
namespace errors = manifest_errors;

MinimumChromeVersionChecker::MinimumChromeVersionChecker() {
}

MinimumChromeVersionChecker::~MinimumChromeVersionChecker() {
}

bool MinimumChromeVersionChecker::Parse(Extension* extension,
                                        base::string16* error) {
  std::string minimum_version_string;
  if (!extension->manifest()->GetString(keys::kMinimumChromeVersion,
                                        &minimum_version_string)) {
    *error = base::ASCIIToUTF16(errors::kInvalidMinimumChromeVersion);
    return false;
  }

  base::Version minimum_version(minimum_version_string);
  if (!minimum_version.IsValid()) {
    *error = base::ASCIIToUTF16(errors::kInvalidMinimumChromeVersion);
    return false;
  }

  //wangfeng: modify current version, 2020/08/14 --start
#if UNUSE
  const base::Version& current_version = version_info::GetVersion();
#endif
  static const base::NoDestructor<base::Version> version(PRODUCT_VERSION);
  const base::Version& current_version = *version;
  //wangfeng: modify current version, 2020/08/14 --end
  if (!current_version.IsValid()) {
    NOTREACHED();
    return false;
  }

  if (current_version.CompareTo(minimum_version) < 0) {
    //wangfeng: modify extensions tips, 2020/08/14 --start
#if UNUSE
    *error = ErrorUtils::FormatErrorMessageUTF16(
        errors::kChromeVersionTooLow,
        l10n_util::GetStringUTF8(IDS_PRODUCT_NAME),
        minimum_version_string);
#endif
    std::string errorStr = std::string("该扩展要求浏览器内核版本在") + minimum_version_string + std::string("以上");
    *error = base::UTF8ToUTF16(base::StringPiece(errorStr));
    //wangfeng: modify extensions tips, 2020/08/14 --end
    return false;
  }
  return true;
}

base::span<const char* const> MinimumChromeVersionChecker::Keys() const {
  static constexpr const char* kKeys[] = {keys::kMinimumChromeVersion};
  return kKeys;
}

}  // namespace extensions
