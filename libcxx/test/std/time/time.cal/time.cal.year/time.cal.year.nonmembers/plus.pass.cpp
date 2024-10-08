//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// UNSUPPORTED: c++03, c++11, c++14, c++17

// <chrono>
// class year;

// constexpr year operator+(const year& x, const years& y) noexcept;
//   Returns: year(int{x} + y.count()).
//
// constexpr year operator+(const years& x, const year& y) noexcept;
//   Returns: y + x

#include <chrono>
#include <cassert>
#include <type_traits>
#include <utility>

#include "test_macros.h"

using year  = std::chrono::year;
using years = std::chrono::years;

constexpr bool test() {
  year y{1223};
  for (int i = 1100; i <= 1110; ++i) {
    year y1 = y + years{i};
    year y2 = years{i} + y;
    assert(y1 == y2);
    assert(static_cast<int>(y1) == i + 1223);
    assert(static_cast<int>(y2) == i + 1223);
  }

  return true;
}

int main(int, char**) {
  ASSERT_NOEXCEPT(std::declval<year>() + std::declval<years>());
  ASSERT_SAME_TYPE(year, decltype(std::declval<year>() + std::declval<years>()));

  ASSERT_NOEXCEPT(std::declval<years>() + std::declval<year>());
  ASSERT_SAME_TYPE(year, decltype(std::declval<years>() + std::declval<year>()));

  test();
  static_assert(test());

  return 0;
}
