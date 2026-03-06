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

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <exception>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <pro.h>
#include <bytes.hpp>
#include <entry.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <graph.hpp>
#include <ida.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>
#ifdef HAS_HEXRAYS
#include <hexrays.hpp>
#endif

#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_format.h"

#include "quokka/Block.h"
#include "quokka/Function.h"
#include "quokka/Imports.h"
#include "quokka/Logger.h"
#include "quokka/ProtoWrapper.h"
#include "quokka/Segment.h"
#include "quokka/Settings.h"
#include "quokka/Util.h"

namespace quokka {

static constexpr Quokka::EdgeType GetEdgeType(size_t out_degree) {
  switch (out_degree) {
    case 0:  // No outgoing edges (end of function)
      return Quokka::EdgeType::Quokka_EdgeType_EDGE_UNKNOWN;
    case 1:  // 1 outgoing edge: unconditional jump
      return Quokka::EdgeType::Quokka_EdgeType_EDGE_JUMP_UNCOND;
    case 2:  // 2 edges -> condition
      return Quokka::EdgeType::Quokka_EdgeType_EDGE_JUMP_COND;
    default:  // 2+ edges -> switch
      return Quokka::EdgeType::Quokka_EdgeType_EDGE_JUMP_INDIR;
  }
}

Function::Function(func_t* func_p) {
  assert(func_p != nullptr);

  this->InitFromAddr(func_p->start_ea);
  this->ExportBody(func_p);
}

Function::Function(ea_t start_, std::string name_) : func_type(TYPE_IMPORTED) {
  this->InitFromAddr(start_);
  this->name = std::move(name_);
}

void Function::InitFromAddr(ea_t addr) {
  this->start_addr = addr;

  try {
    this->segment = &GetSegment(this->start_addr);
  } catch (const std::out_of_range& e) {
    std::throw_with_nested(std::runtime_error(absl::StrFormat(
        "Function at address 0x%x doesn't belong to any segment",
        this->start_addr)));
  }

  this->file_offset = get_fileregion_offset(this->start_addr);

  // Get function name (not mangled)
  this->name = GetName(this->start_addr, false);

  // Get the mangled function name, store it only if different
  std::string mangled_name = GetName(this->start_addr, true);
  if (mangled_name != this->name)
    this->mangled_name = std::move(mangled_name);

  this->ExportPrototype(addr);
}

void Function::ExportPrototype(ea_t addr) {
  tinfo_t tif;
  qstring decl;

  QLOGI << absl::StrFormat("Exporting prototype for function at address 0x%08x",
                           this->start_addr);

  func_t* func = get_func(addr);

  if (func != nullptr) {
    if (!get_tinfo(&tif, addr)) {
      QLOGW << absl::StrFormat(
          "Cannot get type information for function at address 0x%08x: %s",
          this->start_addr, name.c_str());
      return;
    }

    // qstring name;
    // tif.get_type_name(&name);

    if (tif.print(&decl, this->name.c_str(),
                  /*PRTYPE_TYPE |*/ PRTYPE_1LINE | PRTYPE_DEF | PRTYPE_SEMI)) {
      this->prototype = ConvertIdaString(decl);
    }
  }
}

void Function::ExportBody(func_t* func_p) {
  assert(func_p != nullptr);

  qflow_chart_t flow_chart("", func_p, this->start_addr, func_p->end_ea,
                           FC_NOEXT);
  assert(!flow_chart.blocks.empty() &&
         "Cannot export body of an imported function");

  // If it has a body, the function should never be imported
  if (func_p->flags & FUNC_THUNK) {
    this->func_type = TYPE_THUNK;
  } else if (func_p->flags & FUNC_LIB) {
    this->func_type = TYPE_LIBRARY;
  } else {
    this->func_type = TYPE_NORMAL;
  }

  // If we have a thunk, it may be hard afterwards to detect the target
  // of the thunk function, so get it from here.
  // For most architecture, the call will already be identified to the
  // last instruction of the thunk (e.g. for ARM64, x86). However, in
  // ARM, we may have the pattern of ADD in PC. So we add the call here.
  // It will be deduplicated when the references will be sorted
  // afterwards. if (this->func_type == TYPE_THUNK) {
  //   ea_t indirect_jump = BADADDR;
  //   ea_t target = calc_thunk_func_target(func, &indirect_jump);
  //   if (indirect_jump == BADADDR) {
  //     const std::shared_ptr<Block> block = chunk->blocks.back();
  //     ReferenceHolder::GetInstance().emplace_back(
  //         InstructionInstance(chunk, block, block->instructions.size()
  //         - 1), target, REF_CALL);
  //   }
  // }

  /**
   * Check if the imports function are already exported
   * This is the case for ELF file but not PE
   */
  // TODO
  // if (import_manager.IsImport(this->start_addr)) {
  //   function.func_type = TYPE_IMPORTED;
  //   has_exported_imports = true;
  // }

#if IDA_SDK_VERSION < 850
  mutable_graph_t* graph = create_disasm_graph(this->start_addr);
#else
  interactive_graph_t* graph = create_disasm_graph(this->start_addr);
#endif

  // TODO(dm) ASK ida support to export this function
  // graph->create_orthogonal_layout();

  // TODO(dm) If called from command line, the graph is not rendered
  // TODO(dm) ASK Idasupport for a solution
  graph->create_tree_layout();

  bool graph_layout = true;
  if (graph == nullptr || graph->empty()) {
    QLOGW << absl::StrFormat(
        "Cannot export graph for function at address 0x%08x", this->start_addr);
    graph_layout = false;
  }

  assert(!graph_layout || flow_chart.node_qty() == graph->node_qty());

  // Add the blocks
  for (int i = 0; i < flow_chart.node_qty(); ++i) {
    const qbasic_block_t& block = flow_chart.blocks[i];

    // Sanity checks. Never trust IDA
    assert(!block.empty() && block.start_ea != BADADDR &&
           block.end_ea != BADADDR && block.start_ea < block.end_ea);

    // Push block and position
    Block tmp_block(block.start_ea, block.end_ea,
                    RetrieveBlockType(flow_chart.calc_block_type(i)));
    if (graph_layout) {
      const point_t& node_point = graph->nodes[i].center();
      Position pos{Quokka_Function_Position_PositionType_CENTER, node_point.x,
                   node_point.y};
      this->blocks.push_back({std::move(tmp_block), std::move(pos)});
    } else {
      this->blocks.push_back({std::move(tmp_block), std::nullopt});
    }
  }

  // Add the edges. By construction, IDA flowchart indices are the same as
  // ours
  for (int i = 0; i < flow_chart.node_qty(); ++i) {
    const auto& succ = flow_chart.blocks[i].succ;
    for (int j : succ) {
      this->edges.emplace_back(GetEdgeType(succ.size()), i, j);
    }
  }

  // If exporting decompiled code is enabled export function decompiled code
  if (Settings::GetInstance().ExportDecompiledCode()) {
    ExportDecompiledFunction(func_p);
  }
}

void Function::ExportDecompiledFunction(func_t* func_p) {
#ifdef HAS_HEXRAYS
  hexrays_failure_t hf;
  cfuncptr_t cfunc = decompile_func(func_p, &hf);
  qstring decompiled_s;
  qstring_printer_t qp(cfunc, decompiled_s, false);

  // Error codes are documented in:
  // https://cpp.docs.hex-rays.com/group___m_e_r_r__.html#ga124713999eb84ddba531f5c2e9eedcab
  if (hf.code == MERR_OK && cfunc != nullptr) {
    // Print the decompiled code into qstring
    cfunc->print_func(qp);

    // Store the decompiled code into protobuf string
    this->decompiled_code = decompiled_s.c_str();
  } else if (hf.code == MERR_LICENSE) {
    QLOGI << "Hex-Rays license not available, cannot export "
             "decompiled code. Disable export.";
    Settings::GetInstance().SetExportDecompiledCode(false);
  } else if (hf.code == MERR_EXTERN) {
    // do not print anything as extern functions do not have a body
  } else {
    QLOGI << absl::StrFormat(
        "Decompilation failed for function %s at "
        "address 0x%a (%s)",
        this->name, this->start_addr, hf.desc().c_str());
  }
#else
  assert(
      false &&
      "This code should not be reachable, check the preprocessor directives");
#endif
}

std::pair<std::vector<Function>, std::vector<std::pair<ea_t, ea_t>>>
ExportFunctions() {
  bool export_instructions = Settings::GetInstance().ExportInstructions();

  /* Allocate enough space from the start */
  std::vector<Function> functions;
  functions.reserve(get_func_qty());
  std::vector<std::pair<ea_t, ea_t>> chunks;

  // Comments& comments = Comments::GetInstance();
  const ImportManager& import_manager = ImportManager::GetInstance();

  /**
   * We want to iterate over every function in the binary.
   * However, in some cases, the first function is at address 0 which is
   * also the min_ea. Thus, we first check if there is a function at
   * min_ea and if not, we get the next one.
   */
  ea_t begin_addr = inf_get_min_ea();
  func_t* func = get_func(begin_addr);
  if (func == nullptr) {
    func = get_next_func(begin_addr);
  }

  bool has_exported_imports = false;
  for (; func != nullptr; func = get_next_func(func->start_ea)) {
    assert(is_func_entry(func) &&
           "Impossible! Found a func_t that is not an entry");

    // Do not export imported functions right now.
    // We find them while iterating with get_next_func on ELF binaries but
    // not on PEs
    if (import_manager.IsImport(func->start_ea))
      continue;

    // Create the function and increase the ref counter of the segment
    functions.emplace_back(func).segment->ref_count++;

    // TODO
    if (export_instructions) {
      // Export basic blocks with instructions and operands
    } else {
      // Export only basic blocks
    }

    // Export also comments
    // GetFunctionComments(comments, func,
    // std::make_shared<Function>(function));

    // Push the head chunk and the tails chunks
    chunks.push_back({func->start_ea, func->end_ea});
    for (int i = 0; i < func->tailqty; ++i)
      chunks.push_back({func->tails[i].start_ea, func->tails[i].end_ea});
  }

  // Export imported functions
  for (auto const& [address, import] : import_manager.imports) {
    functions.emplace_back(address, import.name).segment->ref_count++;
    chunks.emplace_back(address, address + get_item_size(address));
  }

  // Build set of exported addresses from the entry points table
  const size_t entry_count = get_entry_qty();
  absl::flat_hash_set<ea_t> exported_addrs;
  exported_addrs.reserve(entry_count);
  for (size_t i = 0; i < entry_count; ++i) {
    ea_t addr = get_entry(get_entry_ordinal(i));
    if (addr != BADADDR)
      exported_addrs.insert(addr);
  }

  // Mark functions that have an exported symbol
  for (auto& f : functions)
    if (exported_addrs.contains(f.start_addr))
      f.is_exported = true;

  // Chunks must be sorted
  std::sort(chunks.begin(), chunks.end());

  return {std::move(functions), std::move(chunks)};
}

}  // namespace quokka
