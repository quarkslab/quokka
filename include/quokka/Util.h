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
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

// clang-format off: Compatibility.h must come before ida headers
#include "Compatibility.h"
// clang-format on
#include <pro.h>
#include <bytes.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <ua.hpp>

#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/hash/hash.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"

#include "ProtoHelper.h"
#include "Windows.h"

namespace quokka {

// Simple flag to know if the plugin is loaded/running or it is being
// terminated. This is useful in the destructor for some singleton classes in
// order to avoid annoying circular reference issues.
extern bool is_running;

// Concept for checking that type T is one of the std::variant types not
// considering cv qualifiers
template <typename T, typename Var>
concept IsOneOf = requires(const Var& var) {
  []<typename... VarArgsT>
    requires(std::same_as<std::decay_t<T>, VarArgsT> || ...)
  (const std::variant<VarArgsT...>) {}(var);
};

/**
 * Comparer struct
 * @tparam T A generic type
 */
template <typename T>
struct Comparer {
  /**
   * Compare the two shared pointed elements by looking at their pointee
   * objects
   * @param a First element
   * @param b Second element
   * @return Boolean
   */
  bool operator()(const std::shared_ptr<T>& a,
                  const std::shared_ptr<T>& b) const {
    return *a == *b;
  }
};

/**
 * Hasher
 * @tparam T Generic type (must implement hashable)
 */
template <typename T>
struct Hasher {
  /**
   * Retrieve the hash of element
   * @param elem Element to hash
   * @return
   */
  size_t operator()(const std::shared_ptr<T>& elem) const {
    return absl::Hash<T>()(*elem);
  }
};

/**
 * ---------------------------------------------
 * quokka::BucketNew
 * ---------------------------------------------
 * Bucket representation
 *
 * A bucket is a deduplicated container where every element is only stored
 * once and everytime a new element already existing is added, the reference
 * count is incremented.
 *
 * @tparam P A descendant of ProtoHelper type
 */
template <typename P>
class BucketNew {
 private:
  using custom_set =
      absl::flat_hash_set<std::shared_ptr<P>, Hasher<P>, Comparer<P>>;

  /**
   * The bucket where elements are kept
   */
  custom_set bucket;

 public:
  using iterator = typename custom_set::iterator;
  using const_iterator = typename custom_set::const_iterator;

  /**
   * Add P to the bucket
   *
   * This creates P if it does not exists or increment the reference counter.
   *
   * @tparam Args Arguments
   * @param args arguments
   * @return A pointer to P
   */
  template <typename... Args>
  std::shared_ptr<P> emplace(Args&&... args) {
    static_assert(std::is_base_of<ProtoHelper, P>::value,
                  "P must inherit from ProtoHelper");
    auto [it, result] =
        bucket.emplace(std::make_shared<P>(std::forward<Args>(args)...));
    (*it)->ref_count++;
    return *it;
  }

  /* Iterators proxy */
  iterator begin() { return bucket.begin(); }
  iterator end() { return bucket.end(); }
  [[nodiscard]] const_iterator begin() const { return bucket.begin(); }
  [[nodiscard]] const_iterator end() const { return bucket.end(); }

  /**
   * Size proxy
   * @return Size of the bucket
   */
  [[nodiscard]] size_t size() const { return bucket.size(); }

  using frequency_map =
      absl::btree_multimap<uint64_t, std::shared_ptr<P>, std::greater<>>;

  /**
   * Sort the element in the bucket by frequency
   *
   * This is used to retrieve first the most common elements.
   *
   * @return A mapping between the reference count and a pointer to its
   * element
   */
  [[nodiscard]] frequency_map SortByFrequency() const {
    frequency_map ordered_map;
    // ordered_map.reserve(bucket.size());
    for (auto const element : bucket) {
      ordered_map.emplace(element->ref_count, element);
    }

    return ordered_map;
  }

  /**
   * Proxy to clear the bucket
   */
  void clear() { this->bucket.clear(); }

  /**
   * Remove an element from the bucket
   *
   * @param key Element to remove
   */
  void erase(const std::shared_ptr<P>& key) { this->bucket.erase(key); }
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

/**
 * Syntax sugar for iterating over a collection of std::variant
 */
static constexpr inline void for_each_visit(auto& collection, auto lambda) {
  for (auto& element : collection) std::visit(lambda, element);
}
static constexpr inline void for_each_ptr_visit(auto& collection, auto lambda) {
  for (auto& element : collection) std::visit(lambda, *element);
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
