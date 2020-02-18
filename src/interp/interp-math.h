/*
 * Copyright 2020 WebAssembly Community Group participants
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WABT_INTERP_MATH_H_
#define WABT_INTERP_MATH_H_

#include <cmath>
#include <limits>
#include <string>
#include <type_traits>

#if COMPILER_IS_MSVC
#include <immintrin.h>
#endif

#include "src/common.h"
#include "src/interp/interp.h"

namespace wabt {
namespace interp {

template <
    typename T,
    typename std::enable_if<!std::is_floating_point<T>::value, int>::type = 0>
bool IsNaN(T val) {
  return false;
}

template <
    typename T,
    typename std::enable_if<std::is_floating_point<T>::value, int>::type = 0>
bool IsNaN(T val) {
  return std::isnan(val);
}

template <
    typename T,
    typename std::enable_if<!std::is_floating_point<T>::value, int>::type = 0>
T CanonNaN(T val) {
  return val;
}

template <
    typename T,
    typename std::enable_if<std::is_floating_point<T>::value, int>::type = 0>
T CanonNaN(T val) {
  if (WABT_UNLIKELY(std::isnan(val))) {
    return std::numeric_limits<f32>::quiet_NaN();
  }
  return val;
}

template <typename T> T ShiftMask(T val) { return val & (sizeof(T)*8-1); }

template <typename T> bool IntEqz(T val) { return val == 0; }
template <typename T> bool Eq(T lhs, T rhs) { return lhs == rhs; }
template <typename T> bool Ne(T lhs, T rhs) { return lhs != rhs; }
template <typename T> bool Lt(T lhs, T rhs) { return lhs < rhs; }
template <typename T> bool Le(T lhs, T rhs) { return lhs <= rhs; }
template <typename T> bool Gt(T lhs, T rhs) { return lhs > rhs; }
template <typename T> bool Ge(T lhs, T rhs) { return lhs >= rhs; }
template <typename T> T IntClz(T val) { return Clz(val); }
template <typename T> T IntCtz(T val) { return Ctz(val); }
template <typename T> T IntPopcnt(T val) { return Popcount(val); }
template <typename T> T IntNot(T val) { return ~val; }
template <typename T> T IntNeg(T val) { return ~val + 1; }
template <typename T> T Add(T lhs, T rhs) { return CanonNaN(lhs + rhs); }
template <typename T> T Sub(T lhs, T rhs) { return CanonNaN(lhs - rhs); }
template <typename T> T Mul(T lhs, T rhs) { return CanonNaN(lhs * rhs); }
template <typename T> T IntAnd(T lhs, T rhs) { return lhs & rhs; }
template <typename T> T IntOr(T lhs, T rhs) { return lhs | rhs; }
template <typename T> T IntXor(T lhs, T rhs) { return lhs ^ rhs; }
template <typename T> T IntShl(T lhs, T rhs) { return lhs << ShiftMask(rhs); }
template <typename T> T IntShr(T lhs, T rhs) { return lhs >> ShiftMask(rhs); }
template <typename T> T IntMin(T lhs, T rhs) { return std::min(lhs, rhs); }
template <typename T> T IntMax(T lhs, T rhs) { return std::max(lhs, rhs); }
template <typename T> T IntAndNot(T lhs, T rhs) { return lhs & ~rhs; }
template <typename T> T IntAvgr(T lhs, T rhs) { return (lhs + rhs + 1) / 2; }
template <typename T> T Xchg(T lhs, T rhs) { return rhs; }

template <typename T> struct Mask { using Type = T; };
template <> struct Mask<f32> { using Type = u32; };
template <> struct Mask<f64> { using Type = u64; };

template <typename T> typename Mask<T>::Type EqMask(T lhs, T rhs) { return lhs == rhs ? -1 : 0; }
template <typename T> typename Mask<T>::Type NeMask(T lhs, T rhs) { return lhs != rhs ? -1 : 0; }
template <typename T> typename Mask<T>::Type LtMask(T lhs, T rhs) { return lhs < rhs ? -1 : 0; }
template <typename T> typename Mask<T>::Type LeMask(T lhs, T rhs) { return lhs <= rhs ? -1 : 0; }
template <typename T> typename Mask<T>::Type GtMask(T lhs, T rhs) { return lhs > rhs ? -1 : 0; }
template <typename T> typename Mask<T>::Type GeMask(T lhs, T rhs) { return lhs >= rhs ? -1 : 0; }

template <typename T>
T IntRotl(T lhs, T rhs) {
  return (lhs << ShiftMask(rhs)) | (lhs >> ShiftMask<T>(-rhs));
}

template <typename T>
T IntRotr(T lhs, T rhs) {
  return (lhs >> ShiftMask(rhs)) | (lhs << ShiftMask<T>(-rhs));
}

// i{32,64}.{div,rem}_s are special-cased because they trap when dividing the
// max signed value by -1. The modulo operation on x86 uses the same
// instruction to generate the quotient and the remainder.
template <typename T,
          typename std::enable_if<std::is_signed<T>::value, int>::type = 0>
bool IsNormalDivRem(T lhs, T rhs) {
  return !(lhs == std::numeric_limits<T>::min() && rhs == -1);
}

template <typename T,
          typename std::enable_if<!std::is_signed<T>::value, int>::type = 0>
bool IsNormalDivRem(T lhs, T rhs) {
  return true;
}

template <typename T>
RunResult IntDiv(T lhs, T rhs, T* out, std::string* out_msg) {
  if (WABT_UNLIKELY(rhs == 0)) {
    *out_msg = "integer divide by zero";
    return RunResult::Trap;
  }
  if (WABT_LIKELY(IsNormalDivRem(lhs, rhs))) {
    *out = lhs / rhs;
    return RunResult::Ok;
  } else {
    *out_msg = "integer overflow";
    return RunResult::Trap;
  }
}

template <typename T>
RunResult IntRem(T lhs, T rhs, T* out, std::string* out_msg) {
  if (WABT_UNLIKELY(rhs == 0)) {
    *out_msg = "integer divide by zero";
    return RunResult::Trap;
  }
  if (WABT_LIKELY(IsNormalDivRem(lhs, rhs))) {
    *out = lhs % rhs;
  } else {
    *out = 0;
  }
  return RunResult::Ok;
}

#if COMPILER_IS_MSVC
template <typename T> T FloatAbs(T val);

// Don't use std::abs directly on MSVC, since that seems to lose the NaN tag.
template <>
f32 FloatAbs(f32 val) {
  return _mm_cvtss_f32(_mm_and_ps(
      _mm_set_ps1(val), _mm_castsi128_ps(_mm_set1_epi32(0x7fffffff))));
}

template <>
f64 FloatAbs(f64 val) {
  return _mm_cvtsd_f64(
      _mm_and_pd(_mm_set_pd1(val),
                 _mm_castsi128_pd(_mm_set1_epi64x(0x7fffffffffffffffull))));
}

#else
template <typename T>
T FloatAbs(T val) {
  return std::abs(val);
}
#endif

template <typename T> T FloatNeg(T val) { return -val; }
template <typename T> T FloatCeil(T val) { return CanonNaN(std::ceil(val)); }
template <typename T> T FloatFloor(T val) { return CanonNaN(std::floor(val)); }
template <typename T> T FloatTrunc(T val) { return CanonNaN(std::trunc(val)); }
template <typename T> T FloatNearest(T val) { return CanonNaN(std::nearbyint(val)); }
template <typename T> T FloatSqrt(T val) { return CanonNaN(std::sqrt(val)); }
template <typename T> T FloatCopysign(T lhs, T rhs) { return std::copysign(lhs, rhs); }

template <typename T>
T FloatDiv(T lhs, T rhs) {
  // IEE754 specifies what should happen when dividing a float by zero, but
  // C/C++ says it is undefined behavior.
  if (WABT_UNLIKELY(rhs == 0)) {
    return std::isnan(lhs) || lhs == 0
               ? std::numeric_limits<T>::quiet_NaN()
               : ((std::signbit(lhs) ^ std::signbit(rhs))
                      ? -std::numeric_limits<T>::infinity()
                      : std::numeric_limits<T>::infinity());
  }
  return CanonNaN(lhs / rhs);
}

template <typename T>
T FloatMin(T lhs, T rhs) {
  if (WABT_UNLIKELY(std::isnan(lhs) || std::isnan(rhs))) {
    return std::numeric_limits<T>::quiet_NaN();
  } else if (WABT_UNLIKELY(lhs == 0 && rhs == 0)) {
    return std::signbit(lhs) ? lhs : rhs;
  } else {
    return std::min(lhs, rhs);
  }
}

template <typename T>
T FloatMax(T lhs, T rhs) {
  if (WABT_UNLIKELY(std::isnan(lhs) || std::isnan(rhs))) {
    return std::numeric_limits<T>::quiet_NaN();
  } else if (WABT_UNLIKELY(lhs == 0 && rhs == 0)) {
    return std::signbit(lhs) ? rhs : lhs;
  } else {
    return std::max(lhs, rhs);
  }
}

template <typename R, typename T> bool CanConvert(T val) { return true; }
template <> inline bool CanConvert<s32, f32>(f32 val) { return val >= -2147483648.f && val < 2147483648.f; }
template <> inline bool CanConvert<s32, f64>(f64 val) { return val >= -2147483648. && val <= 2147483647.; }
template <> inline bool CanConvert<u32, f32>(f32 val) { return val > -1.f && val < 4294967296.f; }
template <> inline bool CanConvert<u32, f64>(f64 val) { return val > -1. && val <= 4294967295.; }
template <> inline bool CanConvert<s64, f32>(f32 val) { return val >= -9223372036854775808.f && val < 9223372036854775808.f; }
template <> inline bool CanConvert<s64, f64>(f64 val) { return val >= -9223372036854775808. && val < 9223372036854775808.; }
template <> inline bool CanConvert<u64, f32>(f32 val) { return val > -1.f && val < 18446744073709551616.f; }
template <> inline bool CanConvert<u64, f64>(f64 val) { return val > -1. && val < 18446744073709551616.; }

template <typename R, typename T>
R Convert(T val) {
  assert((CanConvert<R, T>(val)));
  return static_cast<R>(val);
}

template <>
inline f32 Convert(f64 val) {
  // The WebAssembly rounding mode means that these values (which are > F32_MAX)
  // should be rounded to F32_MAX and not set to infinity. Unfortunately, UBSAN
  // complains that the value is not representable as a float, so we'll special
  // case them.
  const f64 kMin = 3.4028234663852886e38;
  const f64 kMax = 3.4028235677973366e38;
  if (WABT_LIKELY(val >= -kMin && val <= kMin)) {
    return val;
  } else if (WABT_UNLIKELY(val > kMin && val < kMax)) {
    return std::numeric_limits<f32>::max();
  } else if (WABT_UNLIKELY(val > -kMax && val < -kMin)) {
    return -std::numeric_limits<f32>::max();
  } else if (WABT_UNLIKELY(std::isnan(val))) {
    return std::numeric_limits<f32>::quiet_NaN();
  } else {
    return std::copysign(std::numeric_limits<f32>::infinity(), val);
  }
}

template <typename T, int N>
T IntExtend(T val) {
  // Hacker's delight 2.6 - sign extension
  auto bit = T{1} << N;
  auto mask = (bit << 1) - 1;
  return ((val & mask) ^ bit) - bit;
}

template <typename R, typename T>
R IntTruncSat(T val) {
  if (WABT_UNLIKELY(std::isnan(val))) {
    return 0;
  } else if (WABT_UNLIKELY(!CanConvert<R>(val))) {
    return std::signbit(val) ? std::numeric_limits<R>::min()
                             : std::numeric_limits<R>::max();
  } else {
    return static_cast<R>(val);
  }
}

template <typename T> struct SatPromote;
template <> struct SatPromote<s8> { using type = s32; };
template <> struct SatPromote<s16> { using type = s32; };
template <> struct SatPromote<u8> { using type = s32; };
template <> struct SatPromote<u16> { using type = s32; };

template <typename R, typename T>
R Saturate(T val) {
  static_assert(sizeof(R) < sizeof(T), "Incorrect types for Saturate");
  const T min = std::numeric_limits<R>::min();
  const T max = std::numeric_limits<R>::max();
  return val > max ? max : val < min ? min : val;
}

template <typename T, typename U = typename SatPromote<T>::type>
T IntAddSat(T lhs, T rhs) {
  return Saturate<T, U>(lhs + rhs);
}

template <typename T, typename U = typename SatPromote<T>::type>
T IntSubSat(T lhs, T rhs) {
  return Saturate<T, U>(lhs - rhs);
}

}  // namespace interp
}  // namespace wabt

#endif  // WABT_INTERP_MATH_H_
