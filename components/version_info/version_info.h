// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_VERSION_INFO_VERSION_INFO_H_
#define COMPONENTS_VERSION_INFO_VERSION_INFO_H_

#include <string>
#include <vector>
#include "components/version_info/channel.h"

namespace base {
class Version;
}

namespace version_info {

// Returns the product name and version information for UserAgent header,
// e.g. "Chrome/a.b.c.d".
std::string GetProductNameAndVersionForUserAgent();

// Returns the product name, e.g. "Chromium" or "Google Chrome".
std::string GetProductName();

// Returns the version number, e.g. "6.0.490.1".
std::string GetVersionNumber();

// add by hanll,增加版本号,2020/12/25, start
std::string GetUOSVersionNumber();
// add by hanll,增加版本号,2020/12/25, end

// Returns the major component of the version, e.g. "6".
std::string GetMajorVersionNumber();

// Returns the result of GetVersionNumber() as a base::Version.
const base::Version& GetVersion();

// Returns a version control specific identifier of this release.
std::string GetLastChange();

// Returns whether this is an "official" release of the current version, i.e.
// whether knowing GetVersionNumber() is enough to completely determine what
// GetLastChange() is.
bool IsOfficialBuild();

// Returns the OS type, e.g. "Windows", "Linux", "FreeBSD", ...
std::string GetOSType();

// Returns a string equivalent of |channel|, independent of whether the build
// is branded or not and without any additional modifiers.
std::string GetChannelString(Channel channel);

// Returns a list of sanitizers enabled in this build.
std::string GetSanitizerList();

// Returns a vector of a string which split by the delim "."
std::vector<std::string> vStringSplit(const  std::string& s, const std::string& delim=".");

}  // namespace version_info

#endif  // COMPONENTS_VERSION_INFO_VERSION_INFO_H_
