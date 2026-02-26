// Copyright 2022-2023 Quarkslab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * @file Util.h
 * Utilities function for quokka
 */

#ifndef QUOKKA_UTIL_H
#define QUOKKA_UTIL_H

#include <concepts>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

// clang-format off: Compatibility.h must come before ida headers
#include "Compatibility.h"
// clang-format on
#include <pro.h>
#include <idp.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <ua.hpp>

#include "absl/strings/str_format.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"

#include "Logger.h"
#include "ProtoHelper.h"
#include "Windows.h"

namespace quokka {

// two steps needed to force preprocessor to expand macro arguments
#define QK_CONCAT2(a, b) a##b
#define QK_CONCAT(a, b) QK_CONCAT2(a, b)

#define SCOPED_STEP(start_msg, done_msg)                        \
  [[maybe_unused]] auto QK_CONCAT(_scoped_step_, __COUNTER__) = \
      scoped_step((start_msg), (done_msg))

#define SCOPED_BOX_STEP(wait_box_msg, start_msg, done_msg)      \
  [[maybe_unused]] auto QK_CONCAT(_scoped_step_, __COUNTER__) = \
      scoped_step((start_msg), (done_msg), (wait_box_msg))

template <typename T>
struct is_std_variant : std::false_type {};

template <typename... Ts>
struct is_std_variant<std::variant<Ts...>> : std::true_type {};

template <typename T>
concept StdVariant = is_std_variant<std::remove_cvref_t<T>>::value;

template <typename...>
static constexpr bool always_false_v = false;

template <typename T>
struct filter_type_adaptor_t {};

template <typename T>
inline constexpr filter_type_adaptor_t<T> filter_type{};

// Implementation: default = false (covers non-variant Var types)
template <typename T, typename Var>
struct is_one_of_variant : std::false_type {};

// Specialization for std::variant<Ts...>
template <typename T, typename... Ts>
struct is_one_of_variant<T, std::variant<Ts...>>
    : std::bool_constant<(
          std::same_as<std::remove_cvref_t<T>, std::remove_cvref_t<Ts>> ||
          ...)> {};

// Concept for checking that type T is one of the std::variant types (not
// considering cv qualifiers)
template <typename T, typename Var>
concept is_one_of_variant_v =
    is_one_of_variant<T, std::remove_cvref_t<Var>>::value;

/**
 * ---------------------------------------------
 * quokka::Timer
 * ---------------------------------------------
 * Timer utility
 *
 * Used for timing operations
 */
class Timer {
 private:
  absl::Time start = absl::InfinitePast();   ///< Starting time
  absl::Time stop = absl::InfiniteFuture();  ///< Ending time

 public:
  /**
   * Constructor
   */
  Timer() = default;

  /**
   * Constructor with starting time
   * @param t Starting time
   */
  explicit Timer(absl::Time t) { start = t; }

  /**
   * Stop timer at time `t`
   * @param t Time to stop
   */
  void SetStop(absl::Time t) { stop = t; }

  /**
   * Reset the timer
   */
  void Reset() {
    start = absl::Now();
    stop = absl::InfiniteFuture();
  }

  double ElapsedSecondsAndReset() {
    auto seconds = this->ElapsedSeconds(absl::Now());
    this->Reset();
    return seconds;
  }

  /**
   * Compute the duration between stop and start
   * @return Measured time
   */
  absl::Duration Elapsed() {
    assert(stop != absl::InfiniteFuture() && start != absl::InfinitePast() &&
           "Error with timers");
    return absl::Duration(stop - start);
  }

  /**
   * Compute the duration between `t` and start
   * @param t Ending time
   * @return Measured time
   */
  absl::Duration Elapsed(absl::Time t) {
    SetStop(t);
    return Elapsed();
  }

  /**
   * Compute the elapsed time in milliseconds between start and `t`
   * @param t Ending time
   * @return Measured time in milliseconds
   */
  double ElapsedMilliSeconds(absl::Time t) {
    return absl::ToDoubleMilliseconds(Elapsed(t));
  }

  /**
   * Compute the elapsed time in seconds between start and `t`
   * @param t Ending time
   * @return Measured time in seconds
   */
  double ElapsedSeconds(absl::Time t) {
    return absl::ToDoubleSeconds(Elapsed(t));
  }
};

// Concept for checking that all the std::variant types are derived from T
template <typename T, typename Var>
concept AllVariantDeriveFrom = requires(const Var& var) {
  []<typename... VarArgsT>
    requires(std::derived_from<VarArgsT, T> && ...)
  (const std::variant<VarArgsT...>) {}(var);
};

template <std::invocable F>
class scope_exit_guard {
 public:
  explicit scope_exit_guard(F&& f) noexcept(
      std::is_nothrow_move_constructible_v<F>)
      : f_(std::forward<F>(f)) {}

  scope_exit_guard(scope_exit_guard&& other) noexcept(
      std::is_nothrow_move_constructible_v<F>)
      : f_(std::move(other.f_)), active_(std::exchange(other.active_, false)) {}

  scope_exit_guard(const scope_exit_guard&) = delete;
  scope_exit_guard& operator=(const scope_exit_guard&) = delete;
  scope_exit_guard& operator=(scope_exit_guard&&) = delete;

  void release() noexcept { active_ = false; }

  ~scope_exit_guard() noexcept {
    if (!active_)
      return;
    try {
      f_();
    } catch (...) {  // never throw from dtors
    }
  }

 private:
  F f_;
  bool active_ = true;
};

[[nodiscard]] inline auto scoped_step(
    std::string_view start_msg, std::string_view done_msg,
    std::optional<std::string_view> wait_box = std::nullopt) {
  Timer timer(absl::Now());

  if (wait_box && !wait_box->empty()) {
    replace_wait_box("%.*s", static_cast<int>(wait_box->size()),
                     wait_box->data());
  }
  QLOGI << start_msg;

  // Own strings so passing temporaries is always safe.
  std::string done = std::string(done_msg);

  return scope_exit_guard(
      [timer = std::move(timer), done = std::move(done)]() mutable noexcept {
        const auto secs = timer.ElapsedSeconds(absl::Now());
        QLOGI << absl::StrFormat("%s (took: %.2fs)", done, secs);
      });
}

/**
 * Syntax sugar for iterating over a collection of std::variant
 */
static constexpr inline void for_each_visit(auto& collection, auto lambda) {
  for (auto& element : collection) std::visit(lambda, element);
}
static constexpr inline void for_each_ptr_visit(auto& collection, auto lambda) {
  for (auto& element : collection) std::visit(lambda, *element);
}

template <typename B, StdVariant V>
B& UpcastVariant(V& variant) {
  return std::visit([](auto& x) -> B& { return static_cast<B&>(x); }, variant);
}
template <typename B, StdVariant V>
const B& UpcastVariant(const V& variant) {
  return std::visit(
      [](const auto& x) -> const B& { return static_cast<const B&>(x); },
      variant);
}

/**
 * Get the name associated to an address
 *
 * @param address Address to look at
 * @param mangled Should the return name be mangled ?
 * @return Name found (or empty)
 */
std::string GetName(ea_t address, bool mangled = false);

/**
 * Convert an IDA string to a std::string
 *
 * @param ida_string IDA string
 * @return String object
 */
std::string ConvertIdaString(const qstring& ida_string);

/**
 * Replace the file extension in path
 *
 * It will replace the part after the last dot (or the end of the file) with
 * the new extension
 *
 * @param path Input file
 * @param new_extension Extension to set
 * @return New file name
 */
std::string ReplaceFileExtension(std::string_view path,
                                 std::string_view new_extension);

/**
 * Get the processor "ph" variable
 *
 * New for IDA SDK 7.5
 *
 * @return A pointer to the processor object
 */
processor_t* GetProcessor();

/**
 * Retrieve the mnemonic name
 *
 * New in IDA 7.5
 *
 * @param instruction IDA instruction structure
 * @return A string containing the mnemonic
 */
std::string GetMnemonic(const insn_t& instruction);

/**
 * Resolve in-place a typedef or typeref to its final concrete type.
 *
 * Follows the typedef/typeref chain and replaces @p tif with the type info of
 * the underlying concrete type. Does nothing if @p tif is neither a typedef
 * nor a typeref.
 *
 * @param tif The IDA type info to resolve; modified in-place
 */
void ResolveTypedef(tinfo_t& tif);

}  // namespace quokka

#endif  // QUOKKA_UTIL_H
