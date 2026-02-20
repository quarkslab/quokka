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

#include <cstdint>
#include <utility>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <typeinf.hpp>
#include <xref.hpp>

#include "quokka.pb.h"
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

void ExportCodeReference(ea_t address) {
  References& references = References::GetInstance();

  std::vector<ea_t> flow_refs;

  xrefblk_t xref;
  for (bool ok = xref.first_to(address, XREF_DATA); ok; ok = xref.next_to()) {
    references.emplace(xref.from, address,
                       Quokka_Reference_ReferenceType_REF_DATA);
  }
  for (bool ok = xref.first_to(address, XREF_CODE); ok; ok = xref.next_to()) {
    references.emplace(xref.from, address,
                       Quokka_Reference_ReferenceType_REF_CODE);
  }
}

void ExportDataReferences(const Data& data) {
  References& references = References::GetInstance();

  xrefblk_t xref;
  for (bool ok = xref.first_to(data.addr); ok; ok = xref.next_to()) {
    references.emplace(xref.from, data.addr,
                       Quokka_Reference_ReferenceType_REF_DATA);
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

void ExportSymbolReference(const ProtoHelper* type, const tid_t& tid,
                           int32_t index) {
  assert(type != nullptr);
  References& references = References::GetInstance();

  // Symbols only have TO references
  xrefblk_t xref;
  for (bool ok = xref.first_to(tid, XREF_EA); ok; ok = xref.next_to()) {
    references.emplace(xref.from, std::make_pair(type, index),
                       Quokka_Reference_ReferenceType_REF_SYMBOL);
  }
}

}  // namespace quokka