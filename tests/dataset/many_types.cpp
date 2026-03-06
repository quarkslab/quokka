// many_types.cpp
// C++-only weirdness; reuses everything from many_types.c by including it.
//
// Compile with:
// clang++ -std=c++20 -g3 -gdwarf-4 -O0 -fno-omit-frame-pointer -fno-inline \
//    -fno-inline-functions -fno-optimize-sibling-calls -fno-strict-aliasing \
//    -Wall -Wextra -Wno-missing-field-initializers many_types.cpp \
//    -fstandalone-debug -fno-limit-debug-info \
//    -fno-eliminate-unused-debug-types -o many_types_cpp

#include <atomic>
#include <cstdint>
#include <type_traits>

#if defined(__GNUC__) || defined(__clang__)
#define ATTR_VEC(n) __attribute__((vector_size(n)))
#define ATTR_MSABI __attribute__((ms_abi))
#define ATTR_SYSVABI __attribute__((sysv_abi))
#define USED __attribute__((used))
#define SECTION(name) __attribute__((section(name)))
#else
#define ATTR_VEC(n)
#define ATTR_MSABI
#define ATTR_SYSVABI
#define USED
#define SECTION(name)
#endif

#if defined(__clang__)
#define DO_PRAGMA(x) _Pragma(#x)
#define CLANG_DIAG_PUSH DO_PRAGMA(clang diagnostic push)
#define CLANG_DIAG_POP DO_PRAGMA(clang diagnostic pop)
#define CLANG_IGNORE(w) DO_PRAGMA(clang diagnostic ignored w)

// Use like: CLANG_SUPPRESS("-Wself-assign", statement_without_semicolon)
#define CLANG_SUPPRESS(w, stmt) \
  do {                          \
    CLANG_DIAG_PUSH;            \
    CLANG_IGNORE(w);            \
    stmt;                       \
    CLANG_DIAG_POP;             \
  } while (0)
#else
#define CLANG_SUPPRESS(w, stmt) \
  do {                          \
    stmt;                       \
  } while (0)
#endif

// Pull in the common C translation unit (types + globals + helper entry).
#define ENTRYPOINT many_types_c_main  // The C entrypoint
extern "C" {
#include "many_types.c"
}

// -----------------------------------------------------------------------------
// C++-only enums (underlying types, scoped)
// -----------------------------------------------------------------------------

enum class E8 : uint8_t { Z0 = 0, Z1 = 1, Z255 = 255 };
enum class ENeg : int32_t {
  N0 = 0,
  N1 = -1,
  NMin = INT32_MIN,
  NMax = INT32_MAX
};
enum EU64_CPP : uint64_t {
  U0_CPP = 0,
  U1_CPP = 1,
  UTop_CPP = 0xFFFFFFFFFFFFFFFFull
};

// Enum-typed bitfield (C++ only)
struct BitfieldWeird_CPP {
  enum D ed : 2;  // relies on common enum D
  bool b : 1;
  unsigned u : 5;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wbitfield-width"
  char tc : 10;  // Only allowed in C++
#pragma clang diagnostic pop
};

// -----------------------------------------------------------------------------
// ABI-tagged functions (C++ parser stress)
// -----------------------------------------------------------------------------

extern "C" int ATTR_MSABI msabi_fn(int a, int b) { return a + b; }
extern "C" int ATTR_SYSVABI sysvabi_fn(int a, int b) { return a - b; }

// -----------------------------------------------------------------------------
// Vectors + extended integers (compiler-specific)
// -----------------------------------------------------------------------------

#if defined(__GNUC__) || defined(__clang__)
typedef int32_t v4i32 ATTR_VEC(16);
typedef uint8_t v16u8 ATTR_VEC(16);
#endif

#if defined(__SIZEOF_INT128__)
using i128 = __int128;
using u128 = unsigned __int128;
#endif

// -----------------------------------------------------------------------------
// Templates / decltype / dependent types (C++ only)
// -----------------------------------------------------------------------------

template <typename T, size_t N>
struct TArray {
  T data[N];
};

template <typename T>
struct Identity {
  using type = T;
};

template <typename T>
using IdT = typename Identity<T>::type;

template <typename T>
struct TemplateWeird {
  using value_type = T;
  TArray<T, 3> a;
  IdT<T> b;
  decltype(sizeof(T)) sz;
  T (*fn)(T);
};

// -----------------------------------------------------------------------------
// Member pointers, refs, virtuals (C++ only)
// -----------------------------------------------------------------------------

struct MemberPtrHost {
  int x;
  int y;
  int f(int v) { return x + y + v; }
  virtual int vf(int) { return 0; }
};

using MemFnPtr = int (MemberPtrHost::*)(int);
using MemDataPtr = int MemberPtrHost::*;

using LRefInt = int&;
using RRefInt = int&&;

// -----------------------------------------------------------------------------
// Atomics (C++ std::atomic)
// -----------------------------------------------------------------------------

// moved into a section + marked used
USED SECTION(".data.weird") std::atomic<uint32_t> a_u32{0};
USED SECTION(".data.weird") std::atomic<uint8_t> a_u8{0};

// Instantiate template global (forces TemplateWeird<int> and TArray<int,3>)
USED SECTION(".data.weird") TemplateWeird<int> g_twi_cpp{};

// -----------------------------------------------------------------------------
// Global sinks + global "use sites" in mixed sections
// -----------------------------------------------------------------------------

USED SECTION(".data") volatile uint64_t g_sink_u64 = 0;
USED SECTION(".data") volatile uint32_t g_sink_u32 = 0;
USED SECTION(".data") volatile uint8_t g_sink_u8 = 0;
USED SECTION(".data") volatile int g_sink_i = 0;

static int fn_for_template(int x) { return x ^ 0x55; }

// Enums as real global objects (rodata/data/text/bss mix)
USED SECTION(".rodata") const E8 g_e8_ro = E8::Z255;
USED SECTION(".text") const ENeg g_en_text = ENeg::N1;  // weird section
USED ENeg g_en_normal;                                  // normal, uninit
USED SECTION(".data.weird") EU64_CPP g_eu_data = UTop_CPP;
USED SECTION(".bss.weird") E8 g_e8_bss;  // uninitialized

// Bitfield struct objects (mix)
USED SECTION(".bss.weird") BitfieldWeird_CPP g_bf_bss;
USED SECTION(".text") const BitfieldWeird_CPP g_bf_text = {
    FIRST, true, 31};  // weird section

// MemberPtrHost + pointer-to-member globals (mix)
USED SECTION(".data.weird") MemberPtrHost g_mph_data{};
USED SECTION(".bss.weird") MemberPtrHost g_mph_bss;
USED SECTION(".rodata") const MemFnPtr g_memfn_ro = &MemberPtrHost::f;
USED SECTION(".rodata") const MemDataPtr g_memdata_ro = &MemberPtrHost::x;

// Reference typedefs as globals (force int& / int&& into debug info)
USED SECTION(".data.weird") int g_ref_storage = 123;
USED SECTION(".data.weird") int g_rref_storage = 456;
USED LRefInt g_lref_global = g_ref_storage;
USED RRefInt g_rref_global = static_cast<int&&>(g_rref_storage);

// Template-type globals (ensure all template types materialize as data objects)
USED SECTION(".data.weird") TArray<int, 3> g_tarray_data = {{1, 2, 3}};
USED SECTION(".bss.weird")
    Identity<int> g_identity_bss;  // empty type still becomes a symbol
USED SECTION(".data.weird") TemplateWeird<int> g_tw_data = {
    {{0, 0, 0}}, 0, 0, &fn_for_template};

#if defined(__GNUC__) || defined(__clang__)
struct Pun8 {
  v16u8 v;
  uint8_t b[16];
};
struct Puni {
  v4i32 v;
  int32_t i[4];
};

USED SECTION(".data.weird") v16u8 g_vecu8_data{};
USED SECTION(".bss.weird") v4i32 g_veci32_bss{};
USED SECTION(".data.weird") Pun8 g_pun8{};
USED SECTION(".data.weird") Puni g_puni{};
#endif

#if defined(__SIZEOF_INT128__)
USED SECTION(".data.weird") u128 g_u128_data = (u128)1 << 120;
USED SECTION(".data.weird") i128 g_i128_data = (i128)-5;
#endif

// -----------------------------------------------------------------------------
// Global-only touch routine (no locals): create lots of code->data xrefs
// -----------------------------------------------------------------------------

static void use_cpp_only_types() {
  // Enums: force reads/writes from various sections
  g_e8_bss = E8::Z1;
  g_sink_u8 ^= static_cast<uint8_t>(g_e8_ro) ^ static_cast<uint8_t>(g_e8_bss);
  g_sink_i ^= static_cast<int>(g_en_text);
  g_sink_u64 ^= static_cast<uint64_t>(g_eu_data);

  // Underlying-type facts (compile-time) folded into runtime sinks
  g_sink_i ^= (std::is_same_v<std::underlying_type_t<E8>, uint8_t> ? 1 : 0);
  g_sink_i ^= (std::is_same_v<std::underlying_type_t<ENeg>, int32_t> ? 2 : 0);

  // Bitfield objects (write to bss, read from .text const)
  g_bf_bss.ed = FIRST;
  g_bf_bss.b = true;
  g_bf_bss.u = 31;
  g_sink_u32 ^= (uint32_t)g_bf_bss.u ^ (uint32_t)g_bf_text.u;
  g_sink_i ^= (int)g_bf_bss.b ^ (int)g_bf_text.b ^ (int)g_bf_bss.ed;

  // Member pointers / virtual / member data using GLOBAL object
  g_mph_data.x = 1;
  g_mph_data.y = 2;
  g_sink_i ^= (g_mph_data.*g_memfn_ro)(3);
  g_sink_i ^= g_mph_data.*g_memdata_ro;
  g_sink_i ^= g_mph_data.vf(7);

  // Refs (globals)
  g_sink_i ^= g_lref_global;
  g_sink_i ^= g_rref_global;

  // Atomics (globals)
  a_u32.store(123);
  a_u8.store(7);
  g_sink_u32 ^= a_u32.load();
  g_sink_u8 ^= a_u8.load();

#if defined(__GNUC__) || defined(__clang__)
  // Vectors via global storage and global pun unions
  // still forms a use (and keeps it a real object)
  CLANG_SUPPRESS("-Wself-assign", g_vecu8_data = g_vecu8_data);
  CLANG_SUPPRESS("-Wself-assign", g_veci32_bss = g_veci32_bss);

  g_pun8.v = g_vecu8_data;
  g_puni.v = g_veci32_bss;

  g_sink_u8 ^= g_pun8.b[0] ^ g_pun8.b[15];
  g_sink_i ^= g_puni.i[0] ^ g_puni.i[3];
#endif

#if defined(__SIZEOF_INT128__)
  // i128/u128 stored globally; mutate them to force codegen + xrefs
  g_u128_data += (u128)7;
  g_i128_data *= (i128)3;
  g_sink_u64 ^= (uint64_t)(g_u128_data >> 64);
  g_sink_u64 ^= (uint64_t)g_u128_data;
  g_sink_u64 ^= (uint64_t)g_i128_data;
#endif

  // Templates via globals (no locals)
  g_tw_data.a.data[0] = 1;
  g_tw_data.a.data[1] = 2;
  g_tw_data.a.data[2] = 3;
  g_tw_data.b = 4;
  g_tw_data.sz = sizeof(int);
  g_tw_data.fn = &fn_for_template;
  g_sink_i ^= g_tw_data.fn(g_tw_data.a.data[1] + g_tw_data.b);

  g_twi_cpp.fn = &fn_for_template;
  g_twi_cpp.a.data[0] = 9;
  g_twi_cpp.b = 1;
  g_twi_cpp.sz = sizeof(int);
  g_sink_i ^= g_twi_cpp.fn(g_twi_cpp.a.data[0]);

  // Also touch other template-type globals so they don't look dead
  g_sink_i ^= g_tarray_data.data[0] ^ g_tarray_data.data[2];
  g_sink_u64 ^= (uint64_t)(uintptr_t)&g_identity_bss;

  // ABI-tagged functions: call them (xrefs)
  g_sink_i ^= msabi_fn(10, 20);
  g_sink_i ^= sysvabi_fn(30, 5);
}

// -----------------------------------------------------------------------------
// Keep only a handful of locals for stack-var/xref testing
// -----------------------------------------------------------------------------

int main() {
  // Touch C-side stuff (also generates xrefs into the C globals/types)
  ENTRYPOINT();

  // Handful of locals for xref/stack-var testing:
  MemberPtrHost mph_local{};
  BitfieldWeird_CPP bf_local{};
  TemplateWeird<int> tw_local{};

  mph_local.x = 5;
  mph_local.y = 6;
  bf_local.ed = SECOND;
  bf_local.b = false;
  bf_local.u = 17;

  tw_local.a.data[0] = 7;
  tw_local.a.data[1] = 8;
  tw_local.a.data[2] = 9;
  tw_local.b = 10;
  tw_local.sz = sizeof(int);
  tw_local.fn = &fn_for_template;

  // Copy locals into globals (field layout stores + xrefs)
  g_mph_bss = mph_local;
  g_bf_bss = bf_local;
  g_tw_data = tw_local;

  // Force uses so debug/type info includes everything, and xrefs are present
  use_cpp_only_types();

  // Fold locals into sinks so they can't be discarded trivially
  g_sink_i ^= (mph_local.*g_memfn_ro)(3);
  g_sink_i ^= (int)bf_local.u;
  g_sink_i ^= tw_local.fn(tw_local.a.data[0] + tw_local.b);

  return (int)(g_sink_u64 ^ g_sink_u32 ^ g_sink_u8 ^ (uint64_t)g_sink_i);
}
