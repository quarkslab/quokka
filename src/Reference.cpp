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

#include "quokka.pb.h"
#include "quokka/Block.h"
#include "quokka/Data.h"
#include "quokka/DataType.h"
#include "quokka/ProtoHelper.h"

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
  for (bool ok = xref.first_from(address, XREF_DATA); ok;
       ok = xref.next_from()) {
    references.attach_link(&block_xrefs.from,
                           {address, xref.to, reference::REF_DATA});
  }
  for (bool ok = xref.first_from(address, XREF_CODE); ok;
       ok = xref.next_from()) {
    references.attach_link(&block_xrefs.from,
                           {address, xref.to, reference::REF_CODE});
  }
}

void ExportDataReferences(const Data& data) {
  References& references = References::GetInstance();
  DataTypes& data_types = DataTypes::GetInstance();

  // Export TO xref
  xrefblk_t xref;
  for (bool ok = xref.first_to(data.addr); ok; ok = xref.next_to()) {
    data.xrefs.to.push_back(std::addressof(
        references.emplace(xref.from, data.addr, reference::REF_DATA)));
  }

  // Attach link in the FROM xref
  for (bool ok = xref.first_from(data.addr, XREF_EA); ok;
       ok = xref.next_from()) {
    references.attach_link(&data.xrefs.from,
                           {data.addr, xref.to, reference::REF_DATA});
  }
  for (bool ok = xref.first_from(data.addr, XREF_TID); ok;
       ok = xref.next_from()) {
    auto it = data_types.find_by_tid(xref.to);

    // DataTypes should have already been exported by now
    assert(it != data_types.end());
    // references.attach_link(&data.xrefs.from,
    //                        {data.addr, *it, reference::REF_SYMBOL});
  }
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