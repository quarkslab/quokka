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
 * @file Bucket.h
 * Contains some utility classes to hold elements that derive from ProtoHelper
 * (aka buckets)
 */

#ifndef QUOKKA_BUCKET_H
#define QUOKKA_BUCKET_H

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <functional>
#include <iterator>
#include <memory>
#include <ranges>
#include <stdexcept>
#include <type_traits>
#include <vector>

#include <absl/container/btree_map.h>
#include <absl/container/flat_hash_set.h>
#include <absl/hash/hash.h>

#include "ProtoHelper.h"

namespace quokka {

namespace detail {

// Utility class that offers a view over a sorted collection of objects
template <typename Storage, typename T>
  requires requires(Storage const& s) {
    { s.sorted_view } -> std::same_as<const std::vector<const T*>&>;
  }
class SortedViewImpl {
 public:
  explicit SortedViewImpl(std::shared_ptr<const Storage> storage)
      : storage(std::move(storage)),
        deref_view(this->storage->sorted_view |
                   std::views::transform(deref_func)) {
    if (!this->storage)
      throw std::logic_error("SortedViewImpl cannot have a null storage");
  }

  /* Iterators proxy */
  auto begin() const { return deref_view.begin(); }
  auto end() const { return deref_view.end(); }

  size_t size() const { return storage->sorted_view.size(); }

  const T& operator[](size_t index) const {
    if (index >= storage->sorted_view.size())
      throw std::out_of_range("Index out of range");
    return *storage->sorted_view[index];
  }

 private:
  static constexpr auto deref_func = [](const T* p) -> const T& { return *p; };

  std::shared_ptr<const Storage> storage;
  decltype(storage->sorted_view | std::views::transform(deref_func)) deref_view;
};

template <std::derived_from<ProtoHelper> P>
struct CommonStorage {
  std::vector<const P*> sorted_view;  ///< The sorted view
};

template <std::derived_from<ProtoHelper> P>
struct SetStorage : public CommonStorage<P> {
  struct BucketHash {
    using is_transparent = void;

    size_t operator()(const std::unique_ptr<P>& p) const {
      return absl::HashOf(*p);
    }
    size_t operator()(const P& p) const { return absl::HashOf(p); }
  };

  struct BucketEq {
    using is_transparent = void;

    bool operator()(const std::unique_ptr<P>& a,
                    const std::unique_ptr<P>& b) const {
      return *a == *b;
    }
    bool operator()(const std::unique_ptr<P>& a, const P& b) const {
      return *a == b;
    }
    bool operator()(const P& a, const std::unique_ptr<P>& b) const {
      return a == *b;
    }
  };

  absl::flat_hash_set<std::unique_ptr<P>, BucketHash, BucketEq> bucket;

  auto bucket_values() const {
    return bucket |
           std::views::transform(
               [](const std::unique_ptr<P>& p) -> const P& { return *p; });
  }
};

template <typename K, std::derived_from<ProtoHelper> P,
          typename Compare = std::less<K>>
struct MapStorage : public CommonStorage<P> {
  absl::btree_map<K, std::unique_ptr<P>, Compare> bucket;

  auto bucket_values() const {
    return bucket | std::views::values |
           std::views::transform(
               [](const std::unique_ptr<P>& p) -> const P& { return *p; });
  }
};

template <typename K, std::derived_from<ProtoHelper> P,
          typename Compare = std::less<K>>
struct MultiMapStorage : public CommonStorage<P> {
  absl::btree_multimap<K, std::unique_ptr<P>, Compare> bucket;

  auto bucket_values() const {
    return bucket | std::views::values |
           std::views::transform(
               [](const std::unique_ptr<P>& p) -> const P& { return *p; });
  }
};

}  // namespace detail

// Concept that describes a sorted view. The view offers standard iterator
// access, random access and the collection size
template <typename View, typename T>
concept SortedViewT = requires(const View& v, size_t i) {
  { v.begin() } -> std::input_iterator;
  { v.end() } -> std::sentinel_for<decltype(v.begin())>;
  { v.size() } -> std::convertible_to<size_t>;
  { *v.begin() } -> std::same_as<const T&>;
  { v[i] } -> std::same_as<const T&>;
};

// Concept that describes a Storage used for a bucket
template <typename StorageT, typename T>
concept StorageLike = requires(const StorageT& storage) {
  { storage.bucket.size() } -> std::convertible_to<size_t>;
  { storage.bucket_values() } -> std::ranges::input_range;
  requires std::same_as<std::remove_cvref_t<decltype(storage.sorted_view)>,
                        std::vector<const T*>>;
  requires std::convertible_to<
      std::ranges::range_reference_t<decltype(storage.bucket_values())>,
      const T&>;
};

template <std::derived_from<ProtoHelper> P, StorageLike<P> StorageT>
class CommonSortableBucket {
 private:
  bool sorted = false;

 protected:
  /**
   * Internal storage that will be shared between container and views
   */
  std::shared_ptr<StorageT> storage = std::make_shared<StorageT>();

  bool frozen = false;

 public:
  using SortedView = detail::SortedViewImpl<StorageT, P>;

  /**
   * Size proxy
   * @return Size of the bucket
   */
  size_t size() const { return storage->bucket.size(); }

  /**
   * Freeze the container and prepare the sorted view by frequency
   *
   * @return
   */
  void Freeze() {
    if (this->frozen)
      return;

    this->frozen = true;
  }

  void Sort() {
    if (this->sorted)
      return;

    if (!this->frozen)
      this->Freeze();

    storage->sorted_view.clear();
    storage->sorted_view.reserve(this->size());
    for (const auto& e : storage->bucket_values())
      storage->sorted_view.push_back(&e);

    std::sort(
        storage->sorted_view.begin(), storage->sorted_view.end(),
        [](const P* a, const P* b) { return a->ref_count > b->ref_count; });
    this->sorted = true;
  }

  /**
   * Get a view over the element in the bucket sorted by frequency
   *
   * This is used to retrieve first the most common elements.
   *
   * @return A mapping between the reference count and a pointer to its
   * element
   */
  SortedView GetSortedView() const {
    if (!this->frozen)
      throw std::logic_error(
          "Bucket must be frozen before getting the sorted view");
    if (!this->sorted)
      throw std::logic_error(
          "Bucket must be sorted before getting the sorted view");

    return SortedView(storage);
  }
};

/**
 * ---------------------------------------------
 * quokka::SetBucket
 * ---------------------------------------------
 * Bucket representation
 *
 * A bucket is a deduplicated container where every element is only stored
 * once and everytime a new element already existing is added, the reference
 * count is incremented.
 *
 * @note It ensures pointer stability
 *
 * @tparam P A descendant of ProtoHelper type
 */
template <std::derived_from<ProtoHelper> P>
// TODO add hashable and comparable type
class SetBucket : public CommonSortableBucket<P, detail::SetStorage<P>> {
 public:
  /**
   * Add P to the bucket
   *
   * This creates P if it does not exists or increment the reference counter.
   *
   * @tparam Args Arguments
   * @param args arguments
   * @return A const reference to P
   */
  template <typename... Args>
  const P& emplace(Args&&... args) {
    if (this->frozen)
      throw std::logic_error("Cannot insert new elements in a frozen bucket");
    auto [it, result] = this->storage->bucket.insert(
        std::make_unique<P>(std::forward<Args>(args)...));
    (*it)->ref_count++;
    return **it;
  }

  /**
   * Adds the object P to the bucket if it was not already present, otherwise
   * just increments the reference counter.
   *
   * @param obj The object to insert
   * @return A const reference to P
   */
  const P& insert(P obj) {
    if (this->frozen)
      throw std::logic_error("Cannot insert new elements in a frozen bucket");
    auto [it, result] =
        this->storage->bucket.insert(std::make_unique<P>(std::move(obj)));
    (*it)->ref_count++;
    return **it;
  }

  /**
   * Sets the number of slots in the container to the number needed to
   * accomodate at least `count` total elements
   *
   * @param count the number of elements to accomodate
   * @return
   */
  void reserve(size_t count) {
    if (this->frozen)
      throw std::logic_error("Cannot reserve space in a frozen bucket");
    this->storage->bucket.reserve(count);
  }
};

/**
 * ---------------------------------------------
 * quokka::MapBucket
 * ---------------------------------------------
 * Map bucket representation
 *
 * A bucket is a deduplicated container where every element is only stored
 * once and everytime a new element already existing is added, the reference
 * count is incremented. This variant uses a key-value map to store the elements
 * and offers an API to binary search a key.
 *
 * @note It ensures pointer stability
 *
 * @tparam P A descendant of ProtoHelper type
 */
template <typename K, std::derived_from<ProtoHelper> P,
          typename Compare = std::less<K>>
// TODO add hashable and comparable type
class MapBucket
    : public CommonSortableBucket<P, detail::MapStorage<K, P, Compare>> {
 public:
  /**
   * Add P to the bucket
   *
   * This creates P if it does not exists or increment the reference counter.
   *
   * @tparam Args Arguments
   * @param key the key
   * @param args arguments to pass to P constructor
   * @return A const reference to the object P
   */
  template <typename... Args>
  const P& emplace(const K& key, Args&&... args) {
    if (this->frozen)
      throw std::logic_error("Cannot insert new elements in a frozen bucket");

    // Search if it's already in the bucket
    if (auto search = this->storage->bucket.find(key);
        search != this->storage->bucket.end()) {
      ++search->second->ref_count;
      return *search->second;
    }

    // Otherwise insert it
    auto [it, ok] = this->storage->bucket.emplace(
        key, std::make_unique<P>(std::forward<Args>(args)...));
    it->second->ref_count++;
    return *it->second;
  }

  /**
   * Checks if there is an element with the provided key in the container
   *
   * @param key the key
   * @return true if there is such an element, otherwise false
   */
  bool contains(const K& key) const {
    return this->storage->bucket.contains(key);
  }

  const P& operator[](const K& key) const {
    if (!this->contains(key))
      throw std::out_of_range("Key not in the collection");
    return *this->storage->bucket.at(key);
  }
};

/**
 * ---------------------------------------------
 * quokka::MultiMapBucket
 * ---------------------------------------------
 * MultiMap bucket representation
 *
 * A bucket is a deduplicated container where every element is only stored
 * once and everytime a new element already existing is added, the reference
 * count is incremented. This variant uses a key-value map to store the elements
 * and offers an API to binary search a key.
 *
 * @note It ensures pointer stability
 *
 * @tparam P A descendant of ProtoHelper type
 */
template <typename K, std::equality_comparable P,
          typename Compare = std::less<K>>
  requires std::derived_from<P, ProtoHelper>
// TODO add hashable and comparable type
class MultiMapBucket
    : public CommonSortableBucket<P, detail::MultiMapStorage<K, P, Compare>> {
 public:
  /**
   * Add P to the bucket
   *
   * This creates P if it does not exists or increment the reference counter.
   *
   * @tparam Args Arguments
   * @param key the key
   * @param args arguments to pass to P constructor
   * @return A const reference to the object P
   */
  template <typename... Args>
  const P& emplace(const K& key, Args&&... args) {
    if (this->frozen)
      throw std::logic_error("Cannot insert new elements in a frozen bucket");

    // Build the new object and search if it's already in the bucket
    std::unique_ptr<P> new_ptr =
        std::make_unique<P>(std::forward<Args>(args)...);
    for (auto it = this->storage->bucket.find(key);
         it != this->storage->bucket.end(); ++it) {
      if (*it->second == *new_ptr) {
        ++it->second->ref_count;
        return *it->second;
      }
    }

    // Otherwise insert it
    auto it = this->storage->bucket.insert({key, std::move(new_ptr)});
    it->second->ref_count++;
    return *it->second;
  }

  /**
   * Checks if there is an element with the provided key in the container
   *
   * @param key the key
   * @return true if there is such an element, otherwise false
   */
  bool contains(const K& key) const {
    return this->storage->bucket.contains(key);
  }
};

}  // namespace quokka

#endif