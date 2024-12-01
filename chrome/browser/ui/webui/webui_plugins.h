// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_WEBUI_WEBUI_PLUGINS_H_
#define CHROME_BROWSER_UI_WEBUI_WEBUI_PLUGINS_H_

#include "content/public/browser/web_ui_controller.h"
#include "ui/base/layout.h"
#include "base/values.h"

namespace base {
class RefCountedMemory;
class StringValue;
class FundamentalValue;

// FundamentalValue represents the simple fundamental types of values.
class BASE_EXPORT FundamentalValue : public Value {
 public:
  explicit FundamentalValue(bool in_value);
  explicit FundamentalValue(int in_value);
  explicit FundamentalValue(double in_value);
  ~FundamentalValue();

  // Overridden from Value:
  bool GetAsBoolean(bool* out_value);
  bool GetAsInteger(int* out_value);
  // Values of both type TYPE_INTEGER and TYPE_DOUBLE can be obtained as
  // doubles.
  bool GetAsDouble(double* out_value);
  FundamentalValue* DeepCopy();
  bool Equals(const Value* other);

 private:
  union {
    bool boolean_value_;
    int integer_value_;
    double double_value_;
  };
};

class BASE_EXPORT StringValue : public Value {
 public:
  // Initializes a StringValue with a UTF-8 narrow character string.
  explicit StringValue(const std::string& in_value);

  // Initializes a StringValue with a string16.
  explicit StringValue(const string16& in_value);

  ~StringValue();

  // Returns |value_| as a pointer or reference.
  std::string* GetString();
  //std::string& GetString();

  // Overridden from Value:
  bool GetAsString(std::string* out_value);
  bool GetAsString(string16* out_value);
  bool GetAsString(const StringValue** out_value);
  StringValue* DeepCopy();
  bool Equals(const Value* other);

 private:
  std::string value_;
};
}

namespace user_prefs {
class PrefRegistrySyncable;
}

class PluginsUI : public content::WebUIController {
 public:
  explicit PluginsUI(content::WebUI* web_ui);

  static base::RefCountedMemory* GetFaviconResourceBytes(
      ui::ScaleFactor scale_factor);
  static void RegisterProfilePrefs(user_prefs::PrefRegistrySyncable* registry);

 private:
  DISALLOW_COPY_AND_ASSIGN(PluginsUI);
};

#endif  // CHROME_BROWSER_UI_WEBUI_WEBUI_PLUGINS_H_
