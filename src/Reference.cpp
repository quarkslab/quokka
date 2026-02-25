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

#include "quokka/Reference.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <typeinf.hpp>
#include <xref.hpp>

#include "absl/strings/str_format.h"

#include "quokka.pb.h"
#include "quokka/Block.h"
#include "quokka/Data.h"
#include "quokka/DataType.h"
#include "quokka/ProtoHelper.h"
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

static void AttachLinks(std::vector<const Reference*>& xrefs_from, ea_t address,
                        Quokka::Reference::ReferenceType type, int flags = -1) {
  References& references = References::GetInstance();

  // Infer from type
  if (flags == -1) {
    flags = XREF_EA;
    switch (type) {
      case reference::REF_DATA:
        flags |= XREF_DATA;
        break;
      case reference::REF_CODE:
        flags |= XREF_CODE;
        break;
      case reference::REF_SYMBOL:
        flags = XREF_TID;
        break;
      default:
        assert(false);  // Almost certaintly a developer error
        break;
    }
  }

  xrefblk_t xref;
  if (flags == XREF_TID) {
    DataTypes& data_types = DataTypes::GetInstance();

    for (bool ok = xref.first_from(address, flags); ok; ok = xref.next_from()) {
      // If passed a member TID, get_tid_ordinal() resolves the owning local
      // type ordinal, otherwise it resolves the type itself
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

      references.attach_link(
          &xrefs_from,
          {address,
           std::make_pair(
               std::addressof(UpcastVariant<ProtoHelper>(it->second)),
               member_idx),
           type});
    }
  } else {
    for (bool ok = xref.first_from(address, flags); ok; ok = xref.next_from()) {
      references.attach_link(&xrefs_from, {address, xref.to, type});
    }
  }
}

void ExportCodeReference(const Block& block, size_t instr_idx, ea_t address) {
  References& references = References::GetInstance();
  block.xrefs.try_emplace(instr_idx, std::make_unique<Xref>());
  Xref& block_xrefs = *block.xrefs[instr_idx];

  // Export TO xref
  xrefblk_t xref;
  for (bool ok = xref.first_to(address, XREF_DATA); ok; ok = xref.next_to()) {
    block_xrefs.to.push_back(std::addressof(
        references.emplace(xref.from, address, reference::REF_DATA)));
  }
  for (bool ok = xref.first_to(address, XREF_CODE); ok; ok = xref.next_to()) {
    block_xrefs.to.push_back(std::addressof(
        references.emplace(xref.from, address, reference::REF_CODE)));
  }

  // Attach link in the FROM xref
  AttachLinks(block_xrefs.from, address, reference::REF_DATA);
  AttachLinks(block_xrefs.from, address, reference::REF_CODE);
  AttachLinks(block_xrefs.from, address, reference::REF_SYMBOL);
}

void ExportDataReferences(const Data& data) {
  References& references = References::GetInstance();

  // Export TO xref
  xrefblk_t xref;
  for (bool ok = xref.first_to(data.addr); ok; ok = xref.next_to()) {
    data.xrefs.to.push_back(std::addressof(
        references.emplace(xref.from, data.addr, reference::REF_DATA)));
  }

  // Attach link in the FROM xref
  AttachLinks(data.xrefs.from, data.addr, reference::REF_DATA, XREF_EA);
  AttachLinks(data.xrefs.from, data.addr, reference::REF_SYMBOL);
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
  for (bool ok = xref.first_to(tid, XREF_EA); ok; ok = xref.next_to()) {
    xref_to.push_back(std::addressof(references.emplace(
        xref.from, std::make_pair(type, index), reference::REF_SYMBOL)));
  }
}

}  // namespace quokka