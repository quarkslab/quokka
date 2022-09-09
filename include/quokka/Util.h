// Copyright 2022 Quarkslab
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

#include <cstdint>

#include <pro.h>
#include <bytes.hpp>
#include <name.hpp>
#include <unordered_map>

#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/hash/hash.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"

#include "ProtoHelper.h"
#include "Windows.h"

namespace quokka {

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
};

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

}  // namespace quokka

#endif  // QUOKKA_UTIL_H
