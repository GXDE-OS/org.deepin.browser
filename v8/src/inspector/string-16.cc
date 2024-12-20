// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/inspector/string-16.h"

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>

#include "../../third_party/inspector_protocol/crdtp/cbor.h"
#include "src/base/platform/platform.h"
#include "src/inspector/v8-string-conversions.h"
#include "src/numbers/conversions.h"

namespace v8_inspector {

namespace {

bool isASCII(UChar c) { return !(c & ~0x7F); }

bool isSpaceOrNewLine(UChar c) {
  return isASCII(c) && c <= ' ' && (c == ' ' || (c <= 0xD && c >= 0x9));
}

int64_t charactersToInteger(const UChar* characters, size_t length,
                            bool* ok = nullptr) {
  std::vector<char> buffer;
  buffer.reserve(length + 1);
  for (size_t i = 0; i < length; ++i) {
    if (!isASCII(characters[i])) {
      if (ok) *ok = false;
      return 0;
    }
    buffer.push_back(static_cast<char>(characters[i]));
  }
  buffer.push_back('\0');

  char* endptr;
  int64_t result =
      static_cast<int64_t>(std::strtoll(buffer.data(), &endptr, 10));
  if (ok) *ok = !(*endptr);
  return result;
}
}  // namespace

String16::String16(const UChar* characters, size_t size)
    : m_impl(characters, size) {}

String16::String16(const UChar* characters) : m_impl(characters) {}

String16::String16(const char* characters)
    : String16(characters, std::strlen(characters)) {}

String16::String16(const char* characters, size_t size) {
  m_impl.resize(size);
  for (size_t i = 0; i < size; ++i) m_impl[i] = characters[i];
}

String16::String16(const std::basic_string<UChar>& impl) : m_impl(impl) {}

String16::String16(std::basic_string<UChar>&& impl) : m_impl(impl) {}

// static
String16 String16::fromInteger(int number) {
  char arr[50];
  v8::internal::Vector<char> buffer(arr, arraysize(arr));
  return String16(IntToCString(number, buffer));
}

// static
String16 String16::fromInteger(size_t number) {
  const size_t kBufferSize = 50;
  char buffer[kBufferSize];
#if !defined(_WIN32) && !defined(_WIN64)
  v8::base::OS::SNPrintF(buffer, kBufferSize, "%zu", number);
#else
  v8::base::OS::SNPrintF(buffer, kBufferSize, "%Iu", number);
#endif
  return String16(buffer);
}

// static
String16 String16::fromInteger64(int64_t number) {
  char buffer[50];
  v8::base::OS::SNPrintF(buffer, arraysize(buffer), "%" PRId64 "", number);
  return String16(buffer);
}

// static
String16 String16::fromDouble(double number) {
  char arr[50];
  v8::internal::Vector<char> buffer(arr, arraysize(arr));
  return String16(DoubleToCString(number, buffer));
}

// static
String16 String16::fromDouble(double number, int precision) {
  std::unique_ptr<char[]> str(
      v8::internal::DoubleToPrecisionCString(number, precision));
  return String16(str.get());
}

int64_t String16::toInteger64(bool* ok) const {
  return charactersToInteger(characters16(), length(), ok);
}

int String16::toInteger(bool* ok) const {
  int64_t result = toInteger64(ok);
  if (ok && *ok) {
    *ok = result <= std::numeric_limits<int>::max() &&
          result >= std::numeric_limits<int>::min();
  }
  return static_cast<int>(result);
}

String16 String16::stripWhiteSpace() const {
  if (!length()) return String16();

  size_t start = 0;
  size_t end = length() - 1;

  // skip white space from start
  while (start <= end && isSpaceOrNewLine(characters16()[start])) ++start;

  // only white space
  if (start > end) return String16();

  // skip white space from end
  while (end && isSpaceOrNewLine(characters16()[end])) --end;

  if (!start && end == length() - 1) return *this;
  return String16(characters16() + start, end + 1 - start);
}

String16Builder::String16Builder() = default;

void String16Builder::append(const String16& s) {
  m_buffer.insert(m_buffer.end(), s.characters16(),
                  s.characters16() + s.length());
}

void String16Builder::append(UChar c) { m_buffer.push_back(c); }

void String16Builder::append(char c) {
  UChar u = c;
  m_buffer.push_back(u);
}

void String16Builder::append(const UChar* characters, size_t length) {
  m_buffer.insert(m_buffer.end(), characters, characters + length);
}

void String16Builder::append(const char* characters, size_t length) {
  m_buffer.insert(m_buffer.end(), characters, characters + length);
}

void String16Builder::appendNumber(int number) {
  constexpr int kBufferSize = 11;
  char buffer[kBufferSize];
  int chars = v8::base::OS::SNPrintF(buffer, kBufferSize, "%d", number);
  DCHECK_LE(0, chars);
  m_buffer.insert(m_buffer.end(), buffer, buffer + chars);
}

void String16Builder::appendNumber(size_t number) {
  constexpr int kBufferSize = 20;
  char buffer[kBufferSize];
#if !defined(_WIN32) && !defined(_WIN64)
  int chars = v8::base::OS::SNPrintF(buffer, kBufferSize, "%zu", number);
#else
  int chars = v8::base::OS::SNPrintF(buffer, kBufferSize, "%Iu", number);
#endif
  DCHECK_LE(0, chars);
  m_buffer.insert(m_buffer.end(), buffer, buffer + chars);
}

void String16Builder::appendUnsignedAsHex(uint64_t number) {
  constexpr int kBufferSize = 17;
  char buffer[kBufferSize];
  int chars =
      v8::base::OS::SNPrintF(buffer, kBufferSize, "%016" PRIx64, number);
  DCHECK_LE(0, chars);
  m_buffer.insert(m_buffer.end(), buffer, buffer + chars);
}

void String16Builder::appendUnsignedAsHex(uint32_t number) {
  constexpr int kBufferSize = 9;
  char buffer[kBufferSize];
  int chars = v8::base::OS::SNPrintF(buffer, kBufferSize, "%08" PRIx32, number);
  DCHECK_LE(0, chars);
  m_buffer.insert(m_buffer.end(), buffer, buffer + chars);
}

String16 String16Builder::toString() {
  return String16(m_buffer.data(), m_buffer.size());
}

void String16Builder::reserveCapacity(size_t capacity) {
  m_buffer.reserve(capacity);
}

String16 String16::fromUTF8(const char* stringStart, size_t length) {
  return String16(UTF8ToUTF16(stringStart, length));
}

String16 String16::fromUTF16(const UChar* stringStart, size_t length) {
  return String16(stringStart, length);
}

std::string String16::utf8() const {
  return UTF16ToUTF8(m_impl.data(), m_impl.size());
}

}  // namespace v8_inspector

namespace crdtp {
void SerializerTraits<v8_inspector::String16>::Serialize(
    const v8_inspector::String16& str, std::vector<uint8_t>* out) {
  cbor::EncodeFromUTF16(
      span<uint16_t>(reinterpret_cast<const uint16_t*>(str.characters16()),
                     str.length()),
      out);
}
}  // namespace v8_crdtp
