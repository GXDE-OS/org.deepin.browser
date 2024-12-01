// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/version_info/version_info.h"

#include "base/logging.h"
#include "base/no_destructor.h"
#include "base/sanitizer_buildflags.h"
#include "base/strings/string_number_conversions.h"
#include "base/version.h"
#include "build/branding_buildflags.h"
#include "build/build_config.h"
#include "components/version_info/version_info_values.h"

namespace version_info {

std::string GetProductNameAndVersionForUserAgent() {
  return "Browser/" + GetVersionNumber();
}

std::string GetProductName() {
#if 0
  return PRODUCT_NAME;
#else
  return "Browser";
#endif
}

std::string GetVersionNumber() {
  return PRODUCT_VERSION;
}

// add by hanll,增加版本号,2020/12/25, start
std::string GetUOSVersionNumber() {
  return "5.4.3";
}
// add by hanll,增加版本号,2020/12/25, end

std::string GetMajorVersionNumber() {
  DCHECK(version_info::GetVersion().IsValid());
  return base::NumberToString(version_info::GetVersion().components()[0]);
}

const base::Version& GetVersion() {
  static const base::NoDestructor<base::Version> version(GetVersionNumber());
  return *version;
}

std::string GetLastChange() {
  return LAST_CHANGE;
}

std::vector<std::string> vStringSplit(const  std::string& s, const std::string& delim)
{
    std::vector<std::string> elems;
    size_t pos = 0;
    size_t len = s.length();
    size_t delim_len = delim.length();
    if (delim_len == 0) return elems;
    while (pos < len)
    {
        int find_pos = s.find(delim, pos);
        if (find_pos < 0)
        {
            elems.push_back(s.substr(pos, len - pos));
            break;
        }
        elems.push_back(s.substr(pos, find_pos - pos));
        pos = find_pos + delim_len;
    }
    return elems;
}

bool IsOfficialBuild() {
  // 目前版本规则中，三个数的版本是正式版本，4个数的版本为测试版本。
  size_t length = vStringSplit(GetUOSVersionNumber()).size();
  if(length > 3){
    return false;
  }else{
    return true;
  }

#if 0
  return IS_OFFICIAL_BUILD;
#else
  return true;
#endif
}

std::string GetOSType() {
#if defined(OS_WIN)
  return "Windows";
#elif defined(OS_IOS)
  return "iOS";
#elif defined(OS_MACOSX)
  return "Mac OS X";
#elif defined(OS_CHROMEOS)
# if BUILDFLAG(GOOGLE_CHROME_BRANDING)
  return "Chrome OS";
# else
  return "Chromium OS";
# endif
#elif defined(OS_ANDROID)
  return "Android";
#elif defined(OS_LINUX)
  return "Linux";
#elif defined(OS_FREEBSD)
  return "FreeBSD";
#elif defined(OS_OPENBSD)
  return "OpenBSD";
#elif defined(OS_SOLARIS)
  return "Solaris";
#else
  return "Unknown";
#endif
}

std::string GetChannelString(Channel channel) {
  switch (channel) {
    case Channel::STABLE:
      return "stable";
    case Channel::BETA:
      return "beta";
    case Channel::DEV:
      return "dev";
    case Channel::CANARY:
      return "canary";
    case Channel::UNKNOWN:
      return "unknown";
  }
  NOTREACHED();
  return std::string();
}

std::string GetSanitizerList() {
  std::string sanitizers;
#if defined(ADDRESS_SANITIZER)
  sanitizers += "address ";
#endif
#if BUILDFLAG(IS_HWASAN)
  sanitizers += "hwaddress ";
#endif
#if defined(LEAK_SANITIZER)
  sanitizers += "leak ";
#endif
#if defined(MEMORY_SANITIZER)
  sanitizers += "memory ";
#endif
#if defined(THREAD_SANITIZER)
  sanitizers += "thread ";
#endif
#if defined(UNDEFINED_SANITIZER)
  sanitizers += "undefined ";
#endif
  return sanitizers;
}

}  // namespace version_info
