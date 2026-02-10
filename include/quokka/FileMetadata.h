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
 * @file FileMetadata.h
 * Management of file metadata
 */

#ifndef FILEMETADATA_H
#define FILEMETADATA_H

#include "Compatibility.h"
#include <pro.h>
#include <ida.hpp>
#include <kernwin.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>

#include "absl/flags/internal/path_util.h"
#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_format.h"

#include "ProtoWrapper.h"
#include "Windows.h"

namespace quokka {

/**
 * Processor types
 */
enum ProcName : short {
  PROC_NONE = 0,
  PROC_X86,
  PROC_ARM,
  PROC_PPC,
  PROC_MIPS,
  PROC_GENERIC,
  PROC_DALVIK,
};

/**
 * Type of endianness
 */
enum Endianness : short {
  END_UNK = 0,
  END_LE,  ///< Little endian
  END_BE,  ///< Big endian
};

/**
 * Address size. Only supports 32 or 64 bits.
 */
enum AddressSize : short {
  ADDR_UNK = 0,
  ADDR_64,
  ADDR_32,
};

/**
 * Type of compiler used
 * Rely on IDA compiler detection, may not be reliable.
 */
enum Compiler : short {
  COMPILER_UNK = 0,
  COMPILER_GCC,
  COMPILER_MS,
  COMPILER_BC,
  COMPILER_WATCOM,
  COMPILER_VISAGE,
  COMPILER_BP,
};

/**
 * Calling convention used in the program.
 * @warning There is no support for custom calling convention (set by the
 * user for a specific function)
 */
enum CallingConvention : short {
  CC_UNK = 0,
  CC_CDECL,
  CC_ELLIPSIS,
  CC_STDCALL,
  CC_PASCAL,
  CC_FASTCALL,
  CC_THISCALL,
};

/**
 * Type of hash used on the binary
 */
enum HashType : short {
  HASH_NONE = 0,
  HASH_MD5,
  HASH_SHA256,

};

/**
 * -----------------------------------------------------------------------------
 * quokka::Hash
 * -----------------------------------------------------------------------------
 * Store the information about the hash of the input file
 */
struct Hash {
  HashType type = HASH_NONE;  ///< Type of hash
  std::string value;          ///< Hexdigest of the hash
};

/**
 * -----------------------------------------------------------------------------
 * quokka::Metadata
 * -----------------------------------------------------------------------------
 * Store the data on the input file metadata
 */
class Metadata {
 public:
  Hash file_hash;         ///< File hash data
  std::string file_name;  ///< Name of the input file

  /**
   * Base address.
   * This is one of the most important field of the export because every
   * other address will be stored as an offset to the this base address.
   */
  ea_t base_addr = BADADDR;

  ProcName proc_name = PROC_NONE;                 ///< Detected processor
  AddressSize address_size = ADDR_UNK;            ///< Detected address size
  Endianness endianness = END_UNK;                ///< Detected endianness
  Compiler compiler = COMPILER_UNK;               ///< Detected processor
  CallingConvention calling_convention = CC_UNK;  ///< Detected calling conv

  int ida_version = 0;  ///< Ida version for this export

  bool decompilation_activated = false;  ///< Whether decompilation was activated during export

  /**
   * Compute the hash of the input file. Try MD5 first, and fallback as
   * sha256.
   */
  inline void SetHash();

  /**
   * Detect the architecture using `inf.procname`
   */
  inline void SetArchitecture();

  /**
   * Detect the endianness using `inf_is_be`
   */
  inline void SetEndianness();

  /**
   * Detect the address size using `inf_is_64bit`
   */
  inline void SetAddressSize();

  /**
   * Retrieve the input filename (without path)
   */
  inline void SetFileName();

  /**
   * Detect compiler using `inf_get_cc_id`
   * Conservative detection, if IDA is unsure, will set `COMPILER_UNK`
   */
  inline void SetCompiler();

  /**
   * Detect calling convention using `inf_get_cc_cm`
   */
  inline void SetCallingConvention();

  /**
   * Detect base address using `get_imagebase`
   */
  inline void SetBaseAddr();

  /**
   * Set `IDA_SDK_VERSION`
   */
  inline void SetIdaVersion();

  /**
   * Set decompilation_activated field
   */
  inline void SetDecompilationActivated(bool activated);
};

/**
 * Retrieve the input file sha256 hash
 * @return The lowercase hexdigest of the hash
 */
inline std::string GetInputFileSha256();

/**
 * Retrieve the input file MD5 hash
 * @return The lowercase hexdigest of the hash
 */
inline std::string GetInputFileMd5();

/**
 * Export all the metadata of the input file
 *
 * This will mostly iterate through the inf structure of IDA and retrieve
 * every pertinent information we want to keep.
 *
 * Finally will write the metadata on the wire.
 *
 * @param proto Main protobuf pointer
 * @return
 */
int ExportMeta(quokka::Quokka* proto);

}  // namespace quokka
#endif