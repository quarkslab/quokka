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
#include <cstdint>
#include <iterator>
#include <memory>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

// clang-format off: Compatibility.h must come before ida headers
#include "Compatibility.h"
// clang-format on
#include <pro.h>
#include <bytes.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <ua.hpp>

#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/time/clock.h"

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

// Concept for checking that type T is one of the std::variant types not
// considering cv qualifiers
template <typename T, typename Var>
concept IsOneOf = requires(const Var& var) {
  []<typename... VarArgsT>
    requires(std::same_as<std::decay_t<T>, VarArgsT> || ...)
  (const std::variant<VarArgsT...>) {}(var);
};

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

/**
 * ---------------------------------------------
 * quokka::RefCounter
 * ---------------------------------------------
 * Reference Counter to ProtoHelper object utility
 *
 * Utility for managing the reference counter of the ProtoHelper objects
 * (protobuf objects). It works also on std::variant whose types are all derived
 * from ProtoHelper.
 * It models a non-owning reference (aka non-null raw pointer). The object
 * referenced should out-live the RefCounter.
 */
template <typename T>
  requires(std::derived_from<T, ProtoHelper> ||
           AllVariantDeriveFrom<ProtoHelper, T>)
class RefCounter {
 public:
  ~RefCounter() noexcept {
    if (auto spt = ptr_.lock()) {
      if constexpr (std::derived_from<T, ProtoHelper>) {
        spt->ref_count--;
      } else {
        std::visit([](const auto& v) { v.ref_count--; }, *spt);
      }
    }
  }

  RefCounter(const std::shared_ptr<T>& obj) : ptr_(obj) {
    if (!obj)
      throw new std::invalid_argument(
          "Cannot have a RefCounter to a null pointer");
    if constexpr (std::derived_from<T, ProtoHelper>) {
      obj->ref_count++;
    } else {
      std::visit([](const auto& v) { v.ref_count++; }, *obj);
    }
  }

  RefCounter(const RefCounter<T>& obj) noexcept : ptr_(obj.ptr_) {
    if (auto spt = ptr_.lock()) {
      if constexpr (std::derived_from<T, ProtoHelper>) {
        spt->ref_count++;
      } else {
        std::visit([](const auto& v) { v.ref_count++; }, *spt);
      }
    }
  }

  RefCounter(RefCounter<T>&& obj) noexcept { std::swap(ptr_, obj.ptr_); }

  RefCounter& operator=(const std::shared_ptr<T>& obj) {
    if (!obj)
      throw new std::invalid_argument(
          "Cannot have a RefCounter to null pointer");
    if (auto spt = ptr_.lock()) {
      if constexpr (std::derived_from<T, ProtoHelper>) {
        spt->ref_count--;
        obj->ref_count++;
      } else {
        std::visit([](const auto& v) { v.ref_count--; }, *spt);
        std::visit([](const auto& v) { v.ref_count++; }, *obj);
      }
    }
    ptr_ = obj;
    return *this;
  }

  RefCounter& operator=(const RefCounter<T>& obj) noexcept {
    if (auto spt = ptr_.lock()) {
      if constexpr (std::derived_from<T, ProtoHelper>)
        spt->ref_count--;
      else
        std::visit([](const auto& v) { v.ref_count--; }, *spt);
    }
    ptr_ = obj.ptr_;
    if (auto spt = ptr_.lock()) {
      if constexpr (std::derived_from<T, ProtoHelper>)
        spt->ref_count++;
      else
        std::visit([](const auto& v) { v.ref_count++; }, *spt);
    }
    return *this;
  }

  RefCounter& operator=(RefCounter<T>&& obj) noexcept {
    if (auto spt = ptr_.lock()) {
      if constexpr (std::derived_from<T, ProtoHelper>)
        spt->ref_count--;
      else
        std::visit([](const auto& v) { v.ref_count--; }, *spt);
    }
    std::swap(ptr_, obj.ptr_);
    return *this;
  }

  const T operator*() const {
    if (auto spt = ptr_.lock()) {
      return *spt;
    } else {
      throw new std::runtime_error("Cannot dereference an expired RefCount");
    }
  }

  const std::shared_ptr<T> operator->() const {
    if (auto spt = ptr_.lock()) {
      return spt;
    } else {
      throw new std::runtime_error("Cannot dereference an expired RefCount");
    }
  }

 private:
  std::weak_ptr<T> ptr_;
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
 * Implementation of a merge adjacent method
 *
 * @see http://coliru.stacked-crooked.com/a/0de073866090972d
 */
template <typename ForwardIterator, typename OutputIterator, typename Equal,
          typename Merge>
void MergeAdjacent(ForwardIterator first, ForwardIterator last,
                   OutputIterator out, Equal equal, Merge merge) {
  for (auto lb = first, ub = last; lb != last; lb = ub)
    *out++ = std::accumulate(
        lb + 1, ub = std::mismatch(lb + 1, last, lb, equal).first, *lb, merge);
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
std::string ReplaceFileExtension(absl::string_view path,
                                 absl::string_view new_extension);

/**
 * Check if the option set will yield to true
 *
 * @param option Parameter to check
 * @return True if option is not empty
 */
bool StrToBoolean(const std::string& option);

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

}  // namespace quokka

#endif  // QUOKKA_UTIL_H
