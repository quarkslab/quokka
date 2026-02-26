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

#include <cassert>
#include <string>
#include <string_view>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <pro.h>
#include <ida.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>

#include "absl/strings/escaping.h"
#include "absl/strings/str_format.h"
#include "absl/time/clock.h"

#include "quokka/FileMetadata.h"
#include "quokka/Util.h"
#include "quokka/Writer.h"
#include "quokka/Settings.h"

namespace quokka {

/**
 * Retrieve the input file sha256 hash
 * @return The lowercase hexdigest of the hash
 */
static inline std::string GetInputFileSha256() {
  unsigned char sha256[32];
  if (!retrieve_input_file_sha256(sha256)) {
    return "";
  }

  return absl::AsciiStrToLower(absl::BytesToHexString(
      std::string_view(reinterpret_cast<const char*>(sha256), 32)));
}

/**
 * Retrieve the input file MD5 hash
 * @return The lowercase hexdigest of the hash
 */
static std::string GetInputFileMd5() {
  unsigned char hash[16];
  if (!retrieve_input_file_md5(hash)) {
    return "";
  }
  return absl::AsciiStrToLower(absl::BytesToHexString(
      std::string_view(reinterpret_cast<const char*>(hash), 16)));
}

void Metadata::SetArchitecture() {
  std::string architecture(ConvertIdaString(inf_get_procname()));
  if (architecture == "metapc") {
    this->proc_name = ProcName::PROC_X86;
  } else if (architecture == "ARM") {
    this->proc_name = ProcName::PROC_ARM;
  } else if (architecture == "PPC") {
    this->proc_name = ProcName::PROC_PPC;
  } else if (architecture == "mipsb" || architecture == "mipsl" ||
             architecture == "mipsr" || architecture == "mipsrl" ||
             architecture == "r5900b" || architecture == "r5900l") {
    this->proc_name = ProcName::PROC_MIPS;
  } else if (architecture == "dalvik") {
    this->proc_name = ProcName::PROC_DALVIK;
  } else {
    this->proc_name = ProcName::PROC_GENERIC;
  }
}

void Metadata::SetEndianness() {
  this->endianness = inf_is_be() ? END_BE : END_LE;
}

void Metadata::SetAddressSize() {
  if (inf_is_64bit()) {
    this->address_size = ADDR_64;
#if IDA_SDK_VERSION >= 760
  } else if (inf_is_32bit_exactly()) {
#else
  } else if (inf_is_32bit()) {
#endif
    this->address_size = ADDR_32;
  } else {
    this->address_size = ADDR_UNK;
  }
}

void Metadata::SetCallingConvention() {
  cm_t calling_flag = inf_get_cc_cm() & CM_CC_MASK;
  switch (calling_flag) {
    case CM_CC_CDECL:
      this->calling_convention = CC_CDECL;
      break;

    case CM_CC_ELLIPSIS:
      this->calling_convention = CC_ELLIPSIS;
      break;

    case CM_CC_STDCALL:
      this->calling_convention = CC_STDCALL;
      break;

    case CM_CC_PASCAL:
      this->calling_convention = CC_PASCAL;
      break;

    case CM_CC_FASTCALL:
      this->calling_convention = CC_FASTCALL;
      break;

    case CM_CC_THISCALL:
      this->calling_convention = CC_THISCALL;
      break;

    default:
      this->calling_convention = CC_UNK;
      break;
  }
}

void Metadata::SetHash() {
  Hash hash_struct;
  std::string hash = GetInputFileMd5();
  if (not hash.empty()) {
    hash_struct.type = HASH_MD5;
    hash_struct.value = hash;
  } else {
    hash = GetInputFileSha256();
    if (not hash.empty()) {
      hash_struct.type = HASH_SHA256;
      hash_struct.value = hash;
    } else {
      return;
    }
  }

  this->file_hash = hash_struct;
}

void Metadata::SetFileName() {
  char root_filename[QMAXPATH] = {0};
  get_root_filename(root_filename, QMAXPATH);

  this->file_name = std::string(root_filename);
}

void Metadata::SetBaseAddr() {
  this->base_addr = get_imagebase();
  assert(this->base_addr != BADADDR && "Problem with the base address");
}

void Metadata::SetIdaVersion() {
  this->ida_version = std::to_string(IDA_SDK_VERSION);
}


void Metadata::SetDecompilationActivated(bool activated) {
  this->decompilation_activated = activated;
}


int ExportMeta(quokka::Quokka* proto) {
  Timer timer(absl::Now());
  QLOG_INFO << "Start to export FileMetadata";

  Metadata metadata = Metadata();

  metadata.SetHash();
  metadata.SetArchitecture();
  metadata.SetEndianness();
  metadata.SetAddressSize();
  metadata.SetFileName();
  metadata.SetCallingConvention();
  metadata.SetBaseAddr();
  metadata.SetIdaVersion();

  // Retrieve whether decompilation was activated and put it in the metadata
  metadata.SetDecompilationActivated(Settings::GetInstance().ExportDecompiledCode());

  WriteMetadata(proto, metadata);
  QLOG_INFO << absl::StrFormat("FileMetadata exported (took: %.2fs)",
                               timer.ElapsedSeconds(absl::Now()));

  return eOk;
}

}  // namespace quokka