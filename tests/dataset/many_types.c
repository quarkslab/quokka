// many_types.c
// C11/C23-only "common" types + decl patterns intended to stress type
// importers/parsers.
//
// Compile with:
// clang -std=c23 -g3 -gdwarf-4 -O0 -fno-omit-frame-pointer -fno-inline \
//    -fno-inline-functions -fno-optimize-sibling-calls -fno-strict-aliasing \
//    -fstandalone-debug -fno-limit-debug-info \
//    -fno-eliminate-unused-debug-types -Wall -Wextra many_types.c \
//    -o many_types_c

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

#ifndef ENTRYPOINT
#define ENTRYPOINT main
#endif

#if defined(__GNUC__) || defined(__clang__)
#define ATTR_PACKED __attribute__((packed))
#define ATTR_ALIGNED(n) __attribute__((aligned(n)))
#define ATTR_UNUSED __attribute__((unused))
#define USED __attribute__((used))
#define SECTION(name) __attribute__((section(name)))
#else
#define ATTR_PACKED
#define ATTR_ALIGNED(n)
#define ATTR_UNUSED
#define USED
#define SECTION(name)
#endif

#ifdef __cplusplus
#define ZINIT \
  {           \
  }
#else
#define ZINIT {0}
#endif

// -----------------------------------------------------------------------------
// Useful functions
// -----------------------------------------------------------------------------

static int op_add(int a, int b) { return a + b; }
static int op_sub(int a, int b) { return a - b; }
static int op_mul(int a, int b) { return a * b; }
static int op_div_safe(int a, int b) { return b ? (a / b) : 0; }
static int op_mod_safe(int a, int b) { return b ? (a % b) : 0; }
static int op_xor(int a, int b) { return a ^ b; }
static int op_and(int a, int b) { return a & b; }
static int op_or(int a, int b) { return a | b; }
static int op_shl_masked(int a, int b) { return a << (b & 7); }
static int op_shr_masked(int a, int b) {
  return (int)(((unsigned)a) >> (b & 7));
}
static int op_max(int a, int b) { return (a > b) ? a : b; }
static int op_min(int a, int b) { return (a < b) ? a : b; }

// -----------------------------------------------------------------------------
// Original-ish types (C-compatible)
// -----------------------------------------------------------------------------

union E {
  uint8_t a[4];
  uint32_t b;
};

// NOTE: In C, no enum underlying type syntax. Keep values and let C++ wrap its
// own.
enum D { FIRST = 0, SECOND, THIRD };

struct C_ {
  bool a;
};
typedef struct C_ C;

struct B {
  int a;
  struct {
    int a;
    int b;
  } b;
  union BB_ {
    struct {
      int a : 16;
      int b : 16;
    } a;
    int b;
  } c;
};

struct A {
  uint8_t a;
  char b;
  unsigned char b1;
  short c;
  uint32_t d;
  long long e;
  float f;
  int g : 7;
  double h;
  bool i;
  char j[20];
  uint16_t k[10];
  struct B l;
  C m;
  enum D n;
  C* o;
  void*** p;
};

// -----------------------------------------------------------------------------
// Extra stress: weird bitfields / aggregates / packing
// -----------------------------------------------------------------------------

struct BitfieldWeird_C {
  signed int s1 : 1;
  unsigned int u1 : 1;
  unsigned int u31 : 31;
  unsigned int : 0;  // alignment boundary
  unsigned int : 3;  // unnamed field
  bool b1 : 1;       // (C++-parse safe; valid C23 too)
  long long ll3 : 3;
  signed char sc7 : 7;
  unsigned short us12 : 12;
};

#pragma pack(push, 1)
struct ATTR_PACKED Packed1_C {
  uint8_t a;
  uint32_t b;
  union {
    uint16_t u16;
    struct {
      uint8_t x;
      uint8_t y;
    } s;
  } u;
#ifdef __clang__
  uint8_t tail[];  // flexible array member
#else
  uint8_t tail[0];
#endif
};
#pragma pack(pop)

struct FAM {
  uint8_t a;
  uint16_t b;
  uint32_t tail[];
};

struct ATTR_ALIGNED(32) Aligned32_C {
  uint8_t pad;
  uint64_t x;
};

union UWeird_C {
  uint64_t u64;
  double d;
  struct {
    uint32_t lo;
    uint32_t hi;
  } parts32;
  struct {
    uint16_t a;
    uint16_t b;
    uint16_t c;
    uint16_t e;
  } parts16;
  uint8_t bytes[8];
};

struct HasAnonAgg_C {
  int tag;
  union {
    struct {
      int a;
      int b;
    } ab;
    struct {
      short c;
      short d;
      short e;
      short f;
    } cdef;
    union UWeird_C uw;
  } u;
};

// -----------------------------------------------------------------------------
// Typedef chains + declarator spaghetti
// -----------------------------------------------------------------------------

typedef uint32_t U32;
typedef U32* PU32;
typedef const U32* PCU32;
typedef PCU32* PPCU32;
typedef const PPCU32* CPPCU32;

typedef int (*Fn1_C)(int);
typedef int (*Fn2_C)(int, ...);
typedef void (*VoidFn_C)(void);

typedef int (*FnArr3_C[3])(int);
typedef int (*(*PtrToFnArr3_C)[3])(int);

typedef int (*(*FnReturningPtrArr_C)(int))[4];
typedef int (*FnTakesPtrToArr_C)(const int (*)[5]);

// -----------------------------------------------------------------------------
// Forward decl / self-ref / incomplete-pointer arrays
// -----------------------------------------------------------------------------

struct Incomplete_C;  // incomplete

struct SelfRef_C {
  struct SelfRef_C* next;
  const struct SelfRef_C* const* chain;
  struct Incomplete_C* ip;
  struct Incomplete_C** ipp;
  struct Incomplete_C* iarr[3];
};

// -----------------------------------------------------------------------------
// Prototypes for helper impls (so we can use them in global initializers)
// -----------------------------------------------------------------------------

static int f_plain_c(int x);
static int f_var_c(int x, ...);
static void f_void_c(void);
static int (*ret_ptrarr_c(int))[4];
static int takes_ptr_to_arr_c(const int (*p)[5]);

// -----------------------------------------------------------------------------
// Global sinks (data) to keep everything "observable"
// -----------------------------------------------------------------------------

USED SECTION(".data") volatile uint64_t g_sink_u64_c = 0;
USED SECTION(".data") volatile uint32_t g_sink_u32_c = 0;
USED SECTION(".data") volatile uint8_t g_sink_u8_c = 0;
USED SECTION(".data") volatile int g_sink_i_c = 0;

// -----------------------------------------------------------------------------
// Globals
// -----------------------------------------------------------------------------

uint32_t v1;
uint64_t v2;
char v3;
uint8_t v4;
int v5;
float v6;
double v7;
int* v8;
uint8_t**** v9;
int v10[10];
char v11[] = "asdasd";
struct A v12;
enum D v13;

/* Single function pointers */
int (*g_fp0)(int, int) = op_add;
int (*const g_fp1_const)(int, int) = op_sub;
int (*g_fp2)(int, int) = NULL;
int (*const* g_p_to_const_fp1)(int,
                               int) = &g_fp1_const;  /* pointer to const fp */
int (*(*const g_const_p_to_fp0))(int, int) = &g_fp0; /* const pointer to fp */

/* Arrays of function pointers */
int (*g_arr_fp8[8])(int, int) = {
    op_add, op_sub, op_mul, op_div_safe, op_mod_safe, NULL, op_xor, op_and,
};

int (*g_arr_fp8_alt[8])(int, int) = {
    op_or, op_shl_masked, op_shr_masked, op_max, op_min, op_add, op_sub, op_mul,
};

/* weird section #1 */
USED SECTION(".rodata.weird") int (*const g_arr_fp4_const[4])(int, int) = {
    op_min,
    op_max,
    op_or,
    op_and,
};

/* Arrays of arrays of function pointers */
int (*g_mat_fp[3][4])(int, int) = {
    {op_add, op_sub, op_mul, op_div_safe},
    {op_mod_safe, op_xor, op_and, NULL},
    {op_or, op_shl_masked, op_shr_masked, op_max},
};

int (*const g_mat_fp_const[2][3])(int, int) = {
    {op_min, op_max, op_add},
    {op_sub, op_mul, op_or},
};

/* Pointer to array of function pointers */
int (*(*g_ptr_to_arr8)[8])(int, int) = &g_arr_fp8;
int (*(*const g_const_ptr_to_arr8)[8])(int, int) = &g_arr_fp8_alt;

/* Pointer to array of const function pointers (array elements are const
 * pointers) */
int (*const (*g_ptr_to_const_arr4)[4])(int, int) = &g_arr_fp4_const;
int (*const (*const g_const_ptr_to_const_arr4)[4])(int, int) = &g_arr_fp4_const;

/* Arrays of pointers to arrays of function pointers */
int (*(*g_arr_of_ptr_to_arr4[3])[4])(int, int) = {
    &g_mat_fp[0],
    &g_mat_fp[1],
    &g_mat_fp[2],
};

int (*(*const g_arr_of_const_ptr_to_arr4[2])[4])(int, int) = {
    &g_mat_fp[2],
    &g_mat_fp[0],
};

/* Pointer to a 2D array of function pointers */
/* weird section #2 */
USED SECTION(".data.fnptr.strange") int (*(*g_ptr_to_mat3x4)[3][4])(int, int) =
    &g_mat_fp;
int (*const (*g_ptr_to_const_mat2x3)[2][3])(int, int) = &g_mat_fp_const;

/* Array of pointers to 2D arrays of function pointers */
int (*(*g_arr_of_ptr_to_mat[2])[3][4])(int, int) = {
    &g_mat_fp,
    &g_mat_fp,
};

/* Pointer to (pointer to array[4] of function pointers) */
int (*(**g_pp_to_arr4)[4])(int, int) = &g_arr_of_ptr_to_arr4[1];

/* A few more mixed-const indirections */
int (*const* const g_const_p_to_const_fp1)(int, int) = &g_fp1_const;
int (*(*g_p_to_mut_fp2))(int, int) = &g_fp2;

struct Packed1_C* g_packed_ptr_c;
struct FAM g_normal_fam;
struct Aligned32_C g_al32_c;
struct BitfieldWeird_C g_bfw_c;
struct HasAnonAgg_C g_haa_c;
union UWeird_C g_uw_c;
struct SelfRef_C g_self_c;

Fn1_C g_fn1_c;
Fn2_C g_fn2_c;
FnArr3_C g_fnarr3_c;
PtrToFnArr3_C g_ptr_to_fnarr3_c;
FnReturningPtrArr_C g_fn_ret_ptrarr_c;
FnTakesPtrToArr_C g_fn_takes_ptr_to_arr_c;

CPPCU32 g_cppcu32_c;

// -----------------------------------------------------------------------------
// Typedef edge-cases (see src/CLAUDE.md#190-200)
// Tests: chains, over primitives, over structs/unions/enums,
//        over arrays, over pointers (to primitive, struct, array, pointer),
//        typedef-over-typedef-array, typedef-over-typedef-pointer,
//        arrays-of-typedef, pointers-to-typedef
// -----------------------------------------------------------------------------

// --- Typedef over primitive (info embedded in tif, use get_real_type) ---
typedef int TdInt;
typedef unsigned char TdByte;
typedef float TdFloat;
typedef double TdDouble;
TdInt g_tdint = 42;
TdByte g_tdbyte = 0xff;
TdFloat g_tdfloat = 3.14f;
TdDouble g_tddouble = 2.718;

// --- Typedef chain over primitive (A -> B -> C, get_next_type_name) ---
typedef TdInt TdInt2;
typedef TdInt2 TdInt3;
TdInt2 g_tdint2 = 100;
TdInt3 g_tdint3 = 200;

// --- Typedef over struct/union/enum ---
typedef struct A TdStructA;
typedef struct B TdStructB;
typedef union E TdUnionE;
typedef union UWeird_C TdUWeird;
typedef enum D TdEnumD;
TdStructA g_td_structa;
TdStructB g_td_structb;
TdUnionE g_td_unione;
TdUWeird g_td_uweird;
TdEnumD g_td_enumd = SECOND;

// --- Typedef over array (tif.is_array(); array info embedded in typedef) ---
typedef int TdIntArr5[5];
typedef uint32_t TdU32Arr3[3];
typedef char TdCharBuf[64];
TdIntArr5 g_td_intarr5 = {10, 20, 30, 40, 50};
TdU32Arr3 g_td_u32arr3 = {0xAA, 0xBB, 0xCC};
TdCharBuf g_td_charbuf = "hello typedef array";

// --- Typedef over array of typedef (typedef -> array -> typedef element) ---
typedef TdInt TdIntArr4[4];
typedef TdByte TdByteArr8[8];
typedef TdStructA TdStructAArr2[2];
typedef TdUnionE TdUnionEArr3[3];
typedef TdEnumD TdEnumDArr3[3];
TdIntArr4 g_td_intarr4 = {1, 2, 3, 4};
TdByteArr8 g_td_bytearr8 = {0, 1, 2, 3, 4, 5, 6, 7};
TdStructAArr2 g_td_structaarr2;
TdUnionEArr3 g_td_unionearr3;
TdEnumDArr3 g_td_enumdarr3 = {FIRST, SECOND, THIRD};

// Typedef chain over array
typedef TdIntArr5 TdIntArr5Alias;
TdIntArr5Alias g_td_intarr5_alias = {5, 4, 3, 2, 1};

// --- Typedef over pointer to primitive (tif.is_ptr(), pointed is primitive) ---
typedef int* TdIntPtr;
typedef const int* TdConstIntPtr;
typedef float* TdFloatPtr;
typedef double* TdDoublePtr;
typedef bool* TdBoolPtr;
TdIntPtr g_td_intptr = (int*)0;
TdConstIntPtr g_td_constintptr = (const int*)0;
TdFloatPtr g_td_floatptr = (float*)0;
TdDoublePtr g_td_doubleptr = (double*)0;
TdBoolPtr g_td_boolptr = (bool*)0;

// --- Typedef over pointer to typedef (typedef -> ptr -> typedef target) ---
typedef TdInt* TdTdIntPtr;
typedef TdFloat* TdTdFloatPtr;
typedef TdByte* TdTdBytePtr;
typedef const TdInt* TdConstTdIntPtr;
typedef TdInt** TdTdIntPtrPtr;
TdTdIntPtr g_td_tdintptr = (TdInt*)0;
TdTdFloatPtr g_td_tdfloatptr = (TdFloat*)0;
TdTdBytePtr g_td_tdbyteptr = (TdByte*)0;
TdConstTdIntPtr g_td_consttdintptr = (const TdInt*)0;
TdTdIntPtrPtr g_td_tdintptrptr = (TdInt**)0;

// Typedef over pointer to typedef struct/union/enum
typedef TdStructA* TdStructAPtr;
typedef const TdStructA* TdConstStructAPtr;
typedef TdUnionE* TdUnionEPtr;
typedef TdEnumD* TdEnumDPtr;
TdStructAPtr g_td_structaptr = (TdStructA*)0;
TdConstStructAPtr g_td_conststructaptr = (const TdStructA*)0;
TdUnionEPtr g_td_unioneptr = (TdUnionE*)0;
TdEnumDPtr g_td_enumdptr = (TdEnumD*)0;

// --- Typedef over pointer to array ---
typedef int (*TdPtrToIntArr4)[4];
typedef uint32_t (*TdPtrToU32Arr3)[3];
TdPtrToIntArr4 g_td_ptr_to_intarr4 = (int (*)[4])0;
TdPtrToU32Arr3 g_td_ptr_to_u32arr3 = (uint32_t (*)[3])0;

// Typedef over pointer to typedef-array
typedef TdIntArr5* TdPtrToTdIntArr5;
typedef TdIntArr4* TdPtrToTdIntArr4;
TdPtrToTdIntArr5 g_td_ptr_to_tdintarr5 = (TdIntArr5*)0;
TdPtrToTdIntArr4 g_td_ptr_to_tdintarr4 = (TdIntArr4*)0;

// --- Typedef over pointer to pointer ---
typedef int** TdIntPtrPtr;
typedef int*** TdIntPtrPtrPtr;
typedef const int* const* TdConstPtrConstInt;
TdIntPtrPtr g_td_intptrptr = (int**)0;
TdIntPtrPtrPtr g_td_intptrptrptr = (int***)0;
TdConstPtrConstInt g_td_constptrconstint = (const int* const*)0;

// Typedef over pointer to pointer to typedef
typedef TdInt** TdTdIntPtrPtr2;
typedef TdInt*** TdTdIntPtrPtrPtr;
TdTdIntPtrPtr2 g_td_tdintptrptr2 = (TdInt**)0;
TdTdIntPtrPtrPtr g_td_tdintptrptrptr = (TdInt***)0;

// --- Typedef chain over pointer ---
typedef TdIntPtr TdIntPtr2;
typedef TdIntPtr2 TdIntPtr3;
TdIntPtr2 g_td_intptr2 = (int*)0;
TdIntPtr3 g_td_intptr3 = (int*)0;

// --- Variables: arrays of typedef'd types ---
TdInt g_arr_tdint[4] = {1, 2, 3, 4};
TdStructA g_arr_tdstructa[2];
TdUnionE g_arr_tdunione[3];
TdEnumD g_arr_tdenumd[3] = {FIRST, SECOND, THIRD};
TdIntPtr g_arr_tdintptr[4] = {(int*)0, (int*)0, (int*)0, (int*)0};
TdTdIntPtr g_arr_tdtdintptr[2] = {(TdInt*)0, (TdInt*)0};

// --- Variables: pointers to typedef'd types ---
TdInt* g_ptr_tdint = (TdInt*)0;
TdStructA* g_ptr_tdstructa = (TdStructA*)0;
TdIntArr5* g_ptr_tdintarr5 = (TdIntArr5*)0;
TdInt3* g_ptr_tdint3 = (TdInt3*)0;
TdIntPtr* g_ptr_tdintptr = (TdIntPtr*)0;
TdIntArr4* g_ptr_tdintarr4 = (TdIntArr4*)0;

// "section zoo" globals to ensure IDA sees typed objects in ro/data/bss/text

// rodata: const typed objects
USED SECTION(".rodata") const enum D g_d_ro = THIRD;
// union E initialized via first member a[4] (portable C/C++)
USED SECTION(".rodata") const union E g_e_ro = {{0x44, 0x33, 0x22, 0x11}};
USED SECTION(".rodata") const union UWeird_C g_uw_ro = {0xdeadbeefcafebabeULL};
USED SECTION(".rodata") const struct HasAnonAgg_C g_haa_ro = {7, {{10, 20}}};

// weird section: put *data* into .text (don't write to it!)
USED SECTION(".text") const
    struct BitfieldWeird_C g_bfw_text = {-1, 1, 0x7fffffffU, 1, 3, 63, 0xfff};

// bss-ish: explicit custom bss section objects (uninitialized)
USED SECTION(".bss.weird") struct A g_a_bss;
USED SECTION(".bss.weird") struct B g_b_bss;
USED SECTION(".bss.weird") C g_c_bss;
USED SECTION(".bss.weird") union E g_e_bss;
USED SECTION(".bss.weird") union UWeird_C g_uw_bss;
USED SECTION(".bss.weird") struct HasAnonAgg_C g_haa_bss;
USED SECTION(".bss.weird") struct SelfRef_C g_sr_bss;
USED SECTION(".bss.weird") struct Incomplete_C* g_incomplete_ptr_bss;

// data: explicit data section objects
USED SECTION(".data.weird") struct A g_a_data = ZINIT;
USED SECTION(".data.weird") struct BitfieldWeird_C g_bfw_data = ZINIT;
USED SECTION(".data.weird") U32 g_u32_data = 0x12345678U;
USED SECTION(".data.weird") PU32 g_pu32_data = &g_u32_data;
USED SECTION(".data.weird") PCU32 g_pcu32_data = &g_u32_data;
USED SECTION(".data.weird") PPCU32 g_ppcu32_data = (PPCU32)&g_pcu32_data;
USED SECTION(".data.weird") CPPCU32 g_cppcu32_data = (CPPCU32)&g_ppcu32_data;

// ensure VoidFn_C is used globally too
USED SECTION(".data.weird") VoidFn_C g_voidfn_c = &f_void_c;

// flexible-array "storage" wrapper to get a real global instance that embeds
// Packed1_C

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
struct Packed1_C_Storage {
  struct Packed1_C h;
  uint8_t tail_storage[8];
};
#pragma clang diagnostic pop
USED SECTION(".data.weird") struct Packed1_C_Storage g_packed_storage = ZINIT;

// function-pointer typedefs used globally in various sections
USED SECTION(".rodata") const Fn1_C g_fn1_ro = &f_plain_c;
USED SECTION(".rodata") const Fn2_C g_fn2_ro = &f_var_c;
USED SECTION(".rodata") const FnReturningPtrArr_C g_fnret_ro = &ret_ptrarr_c;
USED SECTION(".rodata") const FnTakesPtrToArr_C g_fntake_ro =
    &takes_ptr_to_arr_c;

// -----------------------------------------------------------------------------
// Helper impls
// -----------------------------------------------------------------------------

static int f_plain_c(int x) { return x + 1; }
static int f_var_c(int x, ...) { return x ^ 0x1234; }
static void f_void_c(void) { g_sink_i_c ^= 0x55; }

static int (*ret_ptrarr_c(int))[4] {
  static int arr[4] = {1, 2, 3, 4};
  return &arr;
}

static int takes_ptr_to_arr_c(const int (*p)[5]) { return (*p)[0]; }

// -----------------------------------------------------------------------------
// Global-only "touch" routine (no locals): creates code->data xrefs heavily
// -----------------------------------------------------------------------------

static void touch_globals_c(void) {
  // tie together sectioned pointers/objects
  g_cppcu32_c = g_cppcu32_data;

  // point packed pointer at storage-backed header
  g_packed_ptr_c = &g_packed_storage.h;

  // assign from rodata into writable globals
  g_uw_c = g_uw_ro;
  g_haa_c = g_haa_ro;

  // set up self-ref structure in bss
  g_sr_bss.next = &g_sr_bss;
  g_sr_bss.chain = (const struct SelfRef_C* const*)&g_sr_bss.next;
  g_sr_bss.ip = (struct Incomplete_C*)0;
  g_sr_bss.ipp = (struct Incomplete_C**)0;
  g_sr_bss.iarr[0] = (struct Incomplete_C*)0;
  g_self_c = g_sr_bss;

  // set random variables
  g_normal_fam.a = 1;

  // function pointers (globals) and calls through them => xrefs
  g_fn1_c = g_fn1_ro;
  g_fn2_c = g_fn2_ro;
  g_fn_ret_ptrarr_c = g_fnret_ro;
  g_fn_takes_ptr_to_arr_c = g_fntake_ro;

  g_sink_i_c ^= g_fn1_c(10);
  g_sink_i_c ^= g_fn2_c(20, 1, 2, 3);

  // pointer-to-array param usage (avoid locals: use a global array)
  static int g_five[5] = {1, 2, 3, 4, 5};
  const int (*p5)[5] = (const int (*)[5]) & g_five;
  g_sink_i_c ^= g_fn_takes_ptr_to_arr_c(p5);

  // function returning pointer-to-array
  int (*p4)[4] = g_fn_ret_ptrarr_c(0);
  g_sink_i_c ^= (*p4)[0];

  // tie original globals to sinks
  v1 = g_sink_u32_c ^= (uint32_t)g_sink_i_c;
  v2 = g_sink_u64_c ^= (uint64_t)v1;
  v3 = (char)(g_sink_u8_c ^= (uint8_t)v1);
  v4 = (uint8_t)g_sink_u8_c;
  v5 = g_sink_i_c;
  v6 = (float)v1;
  v7 = (double)v2;
  v8 = (int*)&v5;
  v9 = (uint8_t****)0;
  v10[0] = v5;
  v13 = g_d_ro;

  // populate some structured globals (writable)
  g_al32_c.x = 0x1122334455667788ULL;
  g_e_bss.b = 0xAABBCCDDu;
  g_incomplete_ptr_bss = (struct Incomplete_C*)0;

  // "use" the `.text` data by reading it (do not write!)
  g_sink_u32_c ^= (uint32_t)g_bfw_text.us12;

  /* Function pointers */
  g_fp0 = op_mul;
  g_fp2 = op_div_safe;
  g_arr_fp8[5] = op_or;         /* was NULL */
  g_arr_fp8[3] = op_shr_masked; /* replace div */
  g_mat_fp[1][3] = op_min;      /* was NULL */
  g_ptr_to_arr8 = &g_arr_fp8_alt;
  g_arr_of_ptr_to_arr4[0] = &g_mat_fp[2];
  g_arr_of_ptr_to_mat[1] = &g_mat_fp;

  g_sink_u32_c += g_fp0(7, 3);               /* mul => 21 */
  g_sink_u32_c += g_fp1_const(7, 3);         /* sub => 4  */
  g_sink_u32_c += (*g_p_to_const_fp1)(7, 3); /* sub => 4  */
  g_sink_u32_c += (*g_const_p_to_fp0)(8, 2); /* mul => 16 */
  g_sink_u32_c += (*g_p_to_mut_fp2)(9, 2);   /* div => 4  */

  g_sink_u32_c += g_arr_fp8[0](10, 5);                   /* add => 15 */
  g_sink_u32_c += (*g_ptr_to_arr8)[1](3, 2);             /* shl => 12 */
  g_sink_u32_c += (*g_const_ptr_to_arr8)[2](33, 1);      /* shr => 16 */
  g_sink_u32_c += (*g_ptr_to_const_arr4)[0](9, 4);       /* min => 4  */
  g_sink_u32_c += (*g_const_ptr_to_const_arr4)[1](9, 4); /* max => 9  */

  g_sink_u32_c += g_mat_fp[0][2](6, 7);                 /* mul => 42 */
  g_sink_u32_c += g_mat_fp[1][3](6, 7);                 /* min => 6  */
  g_sink_u32_c += (*g_arr_of_ptr_to_arr4[0])[0](12, 3); /* row2[0]=or  => 15 */
  g_sink_u32_c += (*g_arr_of_ptr_to_arr4[1])[1](12, 5); /* row1[1]=xor => 9  */
  g_sink_u32_c +=
      (*g_arr_of_const_ptr_to_arr4[0])[3](12, 5); /* row2[3]=max => 12 */
  g_sink_u32_c += (*(*g_pp_to_arr4))[2](20, 6);   /* row1[2]=and => 4  */

  g_sink_u32_c += (*g_ptr_to_mat3x4)[2][1](1, 3);         /* shl => 8  */
  g_sink_u32_c += (*g_arr_of_ptr_to_mat[1])[0][3](22, 5); /* div => 4  */
  g_sink_u32_c += (*g_ptr_to_const_mat2x3)[1][2](8, 3);   /* or => 11  */

  /* Touch the extra mixed-const alias, too. */
  g_sink_u32_c += (*g_const_p_to_const_fp1)(20, 1); /* sub => 19 */

  /* Touch typedef edge-case globals so they survive optimization */
  g_sink_i_c ^= g_tdint ^ g_tdbyte ^ g_tdint2 ^ g_tdint3;
  g_sink_u32_c += (uint32_t)g_tdfloat;
  g_sink_u64_c ^= (uint64_t)(g_tddouble * 1.0);
  g_td_enumd = THIRD;
  g_td_structa.a = (uint8_t)g_tdint;
  g_td_structb.a = g_tdint2;
  g_td_unione.b = 0xDEAD;
  g_td_uweird.u64 = 0xCAFE;

  g_td_intarr5[0] = g_tdint;
  g_td_u32arr3[0] = (uint32_t)g_tdint2;
  g_td_charbuf[0] = 'X';
  g_td_intarr4[0] = g_tdint3;
  g_td_bytearr8[0] = g_tdbyte;
  g_td_structaarr2[0].a = 1;
  g_td_unionearr3[0].b = 0xBEEF;
  g_td_enumdarr3[0] = THIRD;
  g_td_intarr5_alias[0] = 99;

  g_td_intptr = &g_tdint;
  g_td_constintptr = &g_tdint;
  g_td_floatptr = &g_tdfloat;
  g_td_doubleptr = &g_tddouble;
  g_td_tdintptr = &g_tdint2;
  g_td_tdfloatptr = &g_tdfloat;
  g_td_tdbyteptr = &g_tdbyte;
  g_td_consttdintptr = &g_tdint3;
  g_td_tdintptrptr = &g_td_intptr;
  g_td_structaptr = &g_td_structa;
  g_td_conststructaptr = &g_td_structa;
  g_td_unioneptr = &g_td_unione;
  g_td_enumdptr = &g_td_enumd;

  g_td_ptr_to_intarr4 = (int (*)[4])&g_td_intarr4;
  g_td_ptr_to_u32arr3 = (uint32_t (*)[3])&g_td_u32arr3;
  g_td_ptr_to_tdintarr5 = &g_td_intarr5;
  g_td_ptr_to_tdintarr4 = &g_td_intarr4;

  g_td_intptrptr = (int**)&g_td_intptr;
  g_td_constptrconstint = (const int* const*)&g_td_constintptr;
  g_td_tdintptrptr2 = (TdInt**)&g_td_tdintptr;
  g_td_intptr2 = &g_tdint;
  g_td_intptr3 = &g_tdint2;

  g_arr_tdint[0] = g_tdint;
  g_arr_tdstructa[0].a = 2;
  g_arr_tdunione[0].b = 0xFACE;
  g_arr_tdenumd[0] = THIRD;
  g_arr_tdintptr[0] = &g_tdint;
  g_arr_tdtdintptr[0] = &g_tdint2;

  g_ptr_tdint = &g_tdint;
  g_ptr_tdstructa = &g_td_structa;
  g_ptr_tdintarr5 = &g_td_intarr5;
  g_ptr_tdint3 = &g_tdint3;
  g_ptr_tdintptr = &g_td_intptr;
  g_ptr_tdintarr4 = &g_td_intarr4;

  g_sink_i_c ^= *g_td_intptr ^ *g_td_tdintptr;
  g_sink_i_c ^= (*g_td_ptr_to_intarr4)[0];
  g_sink_i_c ^= (int)(*g_td_ptr_to_tdintarr5)[0];
}

// -----------------------------------------------------------------------------
// Entry: keep only a handful of locals for xref/stack-var testing
// -----------------------------------------------------------------------------

int ENTRYPOINT(void) {
  // only a few locals now, and they're "interesting"
  struct A a_local = ZINIT;
  struct BitfieldWeird_C bf_local = g_bfw_text;  // read from .text section
  union UWeird_C uw_local = g_uw_ro;             // read from rodata

  // assign values to locals (creates xrefs to field layouts)
  a_local.d = g_u32_data;
  a_local.n = g_d_ro;
  a_local.i = true;
  a_local.o = &g_c_bss;
  a_local.p = (void***)0;
  a_local.g = 7;
  bf_local.us12 = 0xabc;

  // copy locals into globals (forces structured stores and xrefs)
  v12 = a_local;
  g_bfw_c = bf_local;
  g_uw_c = uw_local;

  // global-only touching (no locals)
  touch_globals_c();

  // ensure void-fn typedef global is actually used
  g_voidfn_c();

  return (int)(g_sink_u64_c ^ g_sink_u32_c ^ g_sink_u8_c ^
               (uint64_t)g_sink_i_c);
}
