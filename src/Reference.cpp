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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <utility>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <bytes.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include "absl/strings/str_format.h"

#include "quokka.pb.h"
#include "quokka/Block.h"
#include "quokka/Data.h"
#include "quokka/DataType.h"
#include "quokka/ProtoHelper.h"
#include "quokka/Reference.h"
#include "quokka/Util.h"

namespace quokka {

// void GetCodeRefFrom(std::vector<ea_t>& code_refs, ea_t start_addr) {
//   xrefblk_t xref{};
//   for (bool ok = xref.first_to(start_addr, XREF_ALL); ok && xref.iscode;
//        ok = xref.next_to()) {
//     if (xref.type == fl_JN || xref.type == fl_JF || xref.type == fl_F) {
//       code_refs.push_back(xref.from);
//     }
//   }
// }

static Quokka::EdgeType GetXrefType(const xrefblk_t& xref);

static constexpr bool is_indirect_code_operand(const op_t& op) {
  switch (op.type) {
    case o_reg:     // call rax / br xN
    case o_mem:     // call [mem] / jmp [mem] (or ISA-specific memory operand)
    case o_phrase:  // [reg]
    case o_displ:   // [reg+disp]
      return true;
    default:
      return false;
  }
}

static Quokka::EdgeType GetXrefType(const xrefblk_t& xref, const insn_t& insn) {
  if (!xref.iscode)
    return GetXrefType(xref);  // No need for the instruction for data edges

  // Call xref
  if (xref.type == fl_CN || xref.type == fl_CF) {
    // Usually it is operand 0, but scan all operands to be safer across ISAs
    for (int i = 0; i < UA_MAXOP; i++) {
      const op_t& op = insn.ops[i];
      if (op.type == o_void)
        break;

      if (is_indirect_code_operand(op))
        return Quokka::EdgeType::Quokka_EdgeType_EDGE_CALL_INDIR;
    }

    // None of the operands were indirect, so it must be direct
    return Quokka::EdgeType::Quokka_EdgeType_EDGE_CALL;
  }

  // Jump xref
  if (xref.type == fl_JN || xref.type == fl_JF) {
    if (is_indirect_jump_insn(insn))
      return Quokka::EdgeType::Quokka_EdgeType_EDGE_JUMP_INDIR;

    if (processor_t::is_cond_insn(insn) > 0)
      return Quokka::EdgeType::Quokka_EdgeType_EDGE_JUMP_COND;

    return Quokka::EdgeType::Quokka_EdgeType_EDGE_JUMP_UNCOND;
  }

  assert(false);  // Catch everything else. We still have to be implemented that
}

static Quokka::EdgeType GetXrefType(const xrefblk_t& xref) {
  if (xref.iscode) {
    insn_t insn;
    if (decode_insn(&insn, xref.from) == 0) {
      // TODO. HUGE PROBLEM. WHAT TO DO HERE? HOW TO RECOVER?
      throw std::runtime_error(
          "Cannot decode instruction during the extraction of xref");
    }
    return GetXrefType(xref, insn);
  } else {
    switch (xref.type) {
      case dr_W:
        return Quokka::EdgeType::Quokka_EdgeType_EDGE_DATA_WRITE;
      case dr_R:
      case dr_S:  // xref to enum members
        return Quokka::EdgeType::Quokka_EdgeType_EDGE_DATA_READ;
      case dr_O:
        return Quokka::EdgeType::Quokka_EdgeType_EDGE_DATA_INDIR;
    }
  }

  assert(false);  // Catch everything else. We still have to be implemented that
}

static void AttachLinks(std::vector<const Reference*>& xrefs_from, ea_t address,
                        const insn_t* insn = nullptr) {
  References& references = References::GetInstance();

  xrefblk_t xref;
  DataTypes& data_types = DataTypes::GetInstance();

  // Symbol xrefs
  for (bool ok = xref.first_from(address, XREF_TID | XREF_NOFLOW); ok;
       ok = xref.next_from()) {
    // get_tid_ordinal() resolves the parent type ordinal when provided with a
    // member, otherwise it resolves the type itself
    uint32 ord = get_tid_ordinal(xref.to);
    assert(ord != 0);  // Should never happen;

    tinfo_t tif;
    if (!tif.get_numbered_type(ord))
      assert(false);  // Should never happen;

    tid_t parent_tid = tif.get_tid();
    type_uid_t parent_tuid = GetTypeUid(tif);
    int32_t member_idx;
    if (parent_tid == xref.to) {  // xref is pointing to the whole object
      member_idx = reference::WHOLE_TYPE;
    } else {  // xref is pointing to a member
      // on failure, the tinfo_t object becomes empty
      tinfo_t tmp = tif;
      member_idx = tif.get_udm_by_tid(nullptr, xref.to);
      if (member_idx == -1)  // maybe an enum?
        member_idx = tmp.get_edm_by_tid(nullptr, xref.to);

      assert(member_idx != -1);  // Huge problem
    }

    auto it = data_types.find_by_tuid(parent_tuid);
    if (it == data_types.end()) {
      tif.get_numbered_type(ord);

      if (tif.is_typedef() || tif.is_typeref()) {
        QLOGE << absl::StrFormat(
            "Dropping xref from 0x%08llx to typedef/typeref %08llx "
            "(specifically it is 0x%08llx)",
            address, parent_tid, xref.to);
        continue;  // It's kinda ok to lose references to typerefs
      }

      // It's not ok to lose xrefs on real types
      assert(false && "Found a xref to a type that has not been exported!");
    }

    auto edge_type = insn ? GetXrefType(xref, *insn) : GetXrefType(xref);

    references.attach_link(
        &xrefs_from,
        {address,
         std::make_pair(std::addressof(UpcastVariant<ProtoHelper>(it->second)),
                        member_idx),
         edge_type});
  }

  // Code+Data xrefs
  for (bool ok = xref.first_from(address, XREF_NOFLOW); ok;
       ok = xref.next_from()) {
    auto edge_type = insn ? GetXrefType(xref, *insn) : GetXrefType(xref);
    references.attach_link(&xrefs_from, {address, xref.to, edge_type});
  }
}

void ExportCodeReference(const Block& block, size_t instr_idx, ea_t address,
                         const insn_t& insn) {
  References& references = References::GetInstance();
  block.xrefs.try_emplace(instr_idx, std::make_unique<Xref>());
  Xref& block_xrefs = *block.xrefs[instr_idx];

  // Export TO xref
  xrefblk_t xref;
  for (bool ok = xref.first_to(address, XREF_DATA | XREF_NOFLOW); ok;
       ok = xref.next_to()) {
    block_xrefs.to.push_back(std::addressof(
        references.emplace(xref.from, address, GetXrefType(xref))));
  }
  for (bool ok = xref.first_to(address, XREF_CODE | XREF_NOFLOW); ok;
       ok = xref.next_to()) {
    block_xrefs.to.push_back(std::addressof(
        references.emplace(xref.from, address, GetXrefType(xref))));
  }

  // Attach link in the FROM xref
  AttachLinks(block_xrefs.from, address, &insn);
}

void ExportDataReferences(const Data& data) {
  References& references = References::GetInstance();

  // Export TO xref
  xrefblk_t xref;
  for (bool ok = xref.first_to(data.addr, XREF_DATA | XREF_NOFLOW); ok;
       ok = xref.next_to()) {
    assert(!xref.iscode);
    data.xrefs.to.push_back(std::addressof(
        references.emplace(xref.from, data.addr, GetXrefType(xref))));
  }

  // Attach link in the FROM xref
  AttachLinks(data.xrefs.from, data.addr);
}

// void ExportUnkReferences(ea_t current_ea, BucketNew<Data>& data_bucket) {
//   ReferenceHolder& reference_holder = ReferenceHolder::GetInstance();

//   xrefblk_t xref{};
//   uint32_t ref_count = 0;
//   std::shared_ptr<Data> data;

//   for (bool ok = xref.first_to(current_ea, XREF_DATA); ok;
//        ok = xref.next_to()) {
//     if (ref_count == 0) {
//       data = data_bucket.emplace(current_ea, DataType::TYPE_UNK, 1);
//     }

//     reference_holder.emplace_back(data, ea_t(xref.from), REF_DATA);
//     ++ref_count;
//   }

//   if (ref_count > 0) {
//     data->ref_count += (ref_count - 1);
//   }
// }

void ExportSymbolReference(const ProtoHelper* type,
                           std::vector<const Reference*>& xref_to,
                           const tid_t& tid, int32_t index) {
  assert(type != nullptr);
  References& references = References::GetInstance();

  // Symbols only have TO references
  xrefblk_t xref;
  for (bool ok = xref.first_to(tid, XREF_EA | XREF_NOFLOW); ok;
       ok = xref.next_to()) {
    xref_to.push_back(std::addressof(references.emplace(
        xref.from, std::make_pair(type, index), GetXrefType(xref))));
  }
}

}  // namespace quokka