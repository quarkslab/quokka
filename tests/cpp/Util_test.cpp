// Standalone unit tests for utility functions and type traits from quokka.
//
// These tests copy the pure-logic parts of Util.h/Util.cpp that have no
// IDA SDK dependency, allowing them to be built and run without IDA.

#include <concepts>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "gtest/gtest.h"

#include "absl/time/clock.h"
#include "absl/time/time.h"

namespace {

// ---------------------------------------------------------------------------
// Copies of pure-logic utilities from quokka::Util.h (no IDA dependency)
// ---------------------------------------------------------------------------

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
    } catch (...) {
    }
  }

 private:
  F f_;
  bool active_ = true;
};

class Timer {
 private:
  absl::Time start = absl::InfinitePast();
  absl::Time stop = absl::InfiniteFuture();

 public:
  Timer() = default;
  explicit Timer(absl::Time t) { start = t; }

  void SetStop(absl::Time t) { stop = t; }

  void Reset() {
    start = absl::Now();
    stop = absl::InfiniteFuture();
  }

  double ElapsedSecondsAndReset() {
    auto seconds = this->ElapsedSeconds(absl::Now());
    this->Reset();
    return seconds;
  }

  absl::Duration Elapsed() {
    assert(stop != absl::InfiniteFuture() && start != absl::InfinitePast());
    return absl::Duration(stop - start);
  }

  absl::Duration Elapsed(absl::Time t) {
    SetStop(t);
    return Elapsed();
  }

  double ElapsedMilliSeconds(absl::Time t) {
    return absl::ToDoubleMilliseconds(Elapsed(t));
  }

  double ElapsedSeconds(absl::Time t) {
    return absl::ToDoubleSeconds(Elapsed(t));
  }
};

// Type traits copied from Util.h
template <typename T>
struct is_std_variant : std::false_type {};

template <typename... Ts>
struct is_std_variant<std::variant<Ts...>> : std::true_type {};

template <typename T>
concept StdVariant = is_std_variant<std::remove_cvref_t<T>>::value;

template <typename T, typename Var>
struct is_one_of_variant : std::false_type {};

template <typename T, typename... Ts>
struct is_one_of_variant<T, std::variant<Ts...>>
    : std::bool_constant<(
          std::same_as<std::remove_cvref_t<T>, std::remove_cvref_t<Ts>> ||
          ...)> {};

template <typename T, typename Var>
concept is_one_of_variant_v =
    is_one_of_variant<T, std::remove_cvref_t<Var>>::value;

template <typename T, typename... Types>
  requires(sizeof...(Types) >= 1)
inline constexpr bool is_one_of_t =
    (std::same_as<std::remove_cvref_t<T>, std::remove_cvref_t<Types>> || ...);

static constexpr inline void for_each_visit(auto& collection, auto lambda) {
  for (auto& element : collection)
    std::visit(lambda, element);
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

// ---------------------------------------------------------------------------
// scope_exit_guard tests
// ---------------------------------------------------------------------------

TEST(ScopeExitGuard, CallsOnDestruction) {
  bool called = false;
  {
    scope_exit_guard guard([&called] { called = true; });
    EXPECT_FALSE(called);
  }
  EXPECT_TRUE(called);
}

TEST(ScopeExitGuard, ReleasePreventsCalling) {
  bool called = false;
  {
    scope_exit_guard guard([&called] { called = true; });
    guard.release();
  }
  EXPECT_FALSE(called);
}

TEST(ScopeExitGuard, MoveTransfersOwnership) {
  int call_count = 0;
  {
    scope_exit_guard guard1([&call_count] { ++call_count; });
    {
      auto guard2 = std::move(guard1);
      EXPECT_EQ(call_count, 0);
    }
    // guard2 destroyed -> callback invoked once
    EXPECT_EQ(call_count, 1);
  }
  // guard1 destroyed but was moved from -> no additional call
  EXPECT_EQ(call_count, 1);
}

TEST(ScopeExitGuard, MoveAndRelease) {
  int call_count = 0;
  {
    scope_exit_guard guard1([&call_count] { ++call_count; });
    auto guard2 = std::move(guard1);
    guard2.release();
  }
  EXPECT_EQ(call_count, 0);
}

TEST(ScopeExitGuard, ExceptionInCallbackSwallowed) {
  // Destructor should not propagate exceptions
  EXPECT_NO_THROW({
    scope_exit_guard guard([] { throw std::runtime_error("boom"); });
  });
}

// ---------------------------------------------------------------------------
// Timer tests
// ---------------------------------------------------------------------------

TEST(Timer, BasicElapsed) {
  absl::Time start = absl::Now();
  Timer timer(start);
  absl::Time end = start + absl::Seconds(5);
  timer.SetStop(end);
  absl::Duration elapsed = timer.Elapsed();
  EXPECT_DOUBLE_EQ(absl::ToDoubleSeconds(elapsed), 5.0);
}

TEST(Timer, ElapsedMilliseconds) {
  absl::Time start = absl::Now();
  Timer timer(start);
  absl::Time end = start + absl::Milliseconds(1500);
  double ms = timer.ElapsedMilliSeconds(end);
  EXPECT_DOUBLE_EQ(ms, 1500.0);
}

TEST(Timer, ElapsedSeconds) {
  absl::Time start = absl::Now();
  Timer timer(start);
  absl::Time end = start + absl::Seconds(3);
  double sec = timer.ElapsedSeconds(end);
  EXPECT_DOUBLE_EQ(sec, 3.0);
}

TEST(Timer, Reset) {
  Timer timer;
  timer.Reset();
  absl::Time after_reset = absl::Now();
  double elapsed = timer.ElapsedSeconds(after_reset);
  // Should be very small (< 1 second)
  EXPECT_GE(elapsed, 0.0);
  EXPECT_LT(elapsed, 1.0);
}

TEST(Timer, ZeroDuration) {
  absl::Time t = absl::Now();
  Timer timer(t);
  timer.SetStop(t);
  EXPECT_DOUBLE_EQ(absl::ToDoubleSeconds(timer.Elapsed()), 0.0);
}

TEST(Timer, SubMillisecondPrecision) {
  absl::Time start = absl::Now();
  Timer timer(start);
  absl::Time end = start + absl::Microseconds(500);
  double ms = timer.ElapsedMilliSeconds(end);
  EXPECT_DOUBLE_EQ(ms, 0.5);
}

// ---------------------------------------------------------------------------
// Type trait tests
// ---------------------------------------------------------------------------

TEST(TypeTraits, IsStdVariant) {
  EXPECT_TRUE((is_std_variant<std::variant<int, double>>::value));
  EXPECT_TRUE((is_std_variant<std::variant<int>>::value));
  EXPECT_FALSE((is_std_variant<int>::value));
  EXPECT_FALSE((is_std_variant<std::string>::value));
  EXPECT_FALSE((is_std_variant<std::vector<int>>::value));
}

TEST(TypeTraits, StdVariantConcept) {
  EXPECT_TRUE((StdVariant<std::variant<int, double>>));
  EXPECT_TRUE((StdVariant<const std::variant<int>&>));
  EXPECT_TRUE((StdVariant<std::variant<int>&&>));
  EXPECT_FALSE((StdVariant<int>));
  EXPECT_FALSE((StdVariant<std::string>));
}

using TestVariant = std::variant<int, double, std::string>;

TEST(TypeTraits, IsOneOfVariant) {
  EXPECT_TRUE((is_one_of_variant<int, TestVariant>::value));
  EXPECT_TRUE((is_one_of_variant<double, TestVariant>::value));
  EXPECT_TRUE((is_one_of_variant<std::string, TestVariant>::value));
  EXPECT_FALSE((is_one_of_variant<float, TestVariant>::value));
  EXPECT_FALSE((is_one_of_variant<char, TestVariant>::value));
}

TEST(TypeTraits, IsOneOfVariantCvRefQualifiers) {
  EXPECT_TRUE((is_one_of_variant<const int, TestVariant>::value));
  EXPECT_TRUE((is_one_of_variant<int&, TestVariant>::value));
  EXPECT_TRUE((is_one_of_variant<const int&, TestVariant>::value));
  EXPECT_TRUE((is_one_of_variant<int&&, TestVariant>::value));
}

TEST(TypeTraits, IsOneOfVariantNonVariant) {
  // Non-variant type -> always false (base template)
  EXPECT_FALSE((is_one_of_variant<int, int>::value));
  EXPECT_FALSE((is_one_of_variant<int, std::string>::value));
}

TEST(TypeTraits, IsOneOfT) {
  EXPECT_TRUE((is_one_of_t<int, int, double, float>));
  EXPECT_TRUE((is_one_of_t<double, int, double, float>));
  EXPECT_TRUE((is_one_of_t<float, int, double, float>));
  EXPECT_FALSE((is_one_of_t<char, int, double, float>));
  EXPECT_FALSE((is_one_of_t<std::string, int, double>));
}

TEST(TypeTraits, IsOneOfTCvRefQualifiers) {
  EXPECT_TRUE((is_one_of_t<const int, int, double>));
  EXPECT_TRUE((is_one_of_t<int&, int, double>));
  EXPECT_TRUE((is_one_of_t<const double&, int, double>));
}

// ---------------------------------------------------------------------------
// for_each_visit tests
// ---------------------------------------------------------------------------

struct Base {
  virtual int value() const = 0;
  virtual ~Base() = default;
};

struct TypeA : public Base {
  int val;
  explicit TypeA(int v) : val(v) {}
  int value() const override { return val; }
};

struct TypeB : public Base {
  int val;
  explicit TypeB(int v) : val(v) {}
  int value() const override { return val; }
};

TEST(ForEachVisit, VisitsAllElements) {
  using Var = std::variant<TypeA, TypeB>;
  std::vector<Var> collection;
  collection.emplace_back(TypeA{1});
  collection.emplace_back(TypeB{2});
  collection.emplace_back(TypeA{3});

  int sum = 0;
  for_each_visit(collection, [&sum](auto& elem) { sum += elem.value(); });
  EXPECT_EQ(sum, 6);
}

TEST(ForEachVisit, EmptyCollection) {
  using Var = std::variant<TypeA, TypeB>;
  std::vector<Var> collection;
  int count = 0;
  for_each_visit(collection, [&count](auto&) { ++count; });
  EXPECT_EQ(count, 0);
}

TEST(ForEachVisit, SingleElement) {
  using Var = std::variant<TypeA, TypeB>;
  std::vector<Var> collection;
  collection.emplace_back(TypeB{42});

  int result = 0;
  for_each_visit(collection, [&result](auto& elem) { result = elem.value(); });
  EXPECT_EQ(result, 42);
}

TEST(ForEachVisit, MutatesElements) {
  using Var = std::variant<TypeA, TypeB>;
  std::vector<Var> collection;
  collection.emplace_back(TypeA{10});
  collection.emplace_back(TypeB{20});

  for_each_visit(collection, [](auto& elem) { elem.val += 5; });

  EXPECT_EQ(std::get<TypeA>(collection[0]).val, 15);
  EXPECT_EQ(std::get<TypeB>(collection[1]).val, 25);
}

// ---------------------------------------------------------------------------
// UpcastVariant tests
// ---------------------------------------------------------------------------

TEST(UpcastVariant, CastsToBase) {
  using Var = std::variant<TypeA, TypeB>;
  Var v = TypeA{42};
  const Base& base = UpcastVariant<Base>(v);
  EXPECT_EQ(base.value(), 42);
}

TEST(UpcastVariant, CastsConstToBase) {
  using Var = std::variant<TypeA, TypeB>;
  const Var v = TypeB{99};
  const Base& base = UpcastVariant<Base>(v);
  EXPECT_EQ(base.value(), 99);
}

TEST(UpcastVariant, MutableAccess) {
  using Var = std::variant<TypeA, TypeB>;
  Var v = TypeA{10};
  Base& base = UpcastVariant<Base>(v);
  // Modify through base reference
  static_cast<TypeA&>(base).val = 20;
  EXPECT_EQ(std::get<TypeA>(v).val, 20);
}

TEST(UpcastVariant, WorksWithBothAlternatives) {
  using Var = std::variant<TypeA, TypeB>;

  Var va = TypeA{1};
  EXPECT_EQ(UpcastVariant<Base>(va).value(), 1);

  Var vb = TypeB{2};
  EXPECT_EQ(UpcastVariant<Base>(vb).value(), 2);
}

}  // namespace
