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

#include "quokka/Function.h"

#include "quokka/Block.h"
#include "quokka/Comment.h"
#include "quokka/Imports.h"
#include "quokka/Reference.h"
#include "quokka/Util.h"

namespace quokka {

ChunkEdge CreateChunkEdge(EdgeType edge_type,
                          std::shared_ptr<FuncChunk> source_chunk,
                          ea_t source_addr,
                          std::shared_ptr<FuncChunk> dest_chunk,
                          ea_t dest_addr) {
  assert(source_chunk != nullptr && dest_chunk != nullptr &&
         "Both chunks must be defined");

  ChunkEdge chunk_edge = {
      edge_type, ChunkLocalization(source_addr, std::move(source_chunk)),
      ChunkLocalization(dest_addr, std::move(dest_chunk))};
  return chunk_edge;
}

FuncChunk::FuncChunk(ea_t start, func_t* func) {
  this->start_addr = start;
  this->end_addr = func->end_ea;

  qflow_chart_t fchart =
      qflow_chart_t("", nullptr, start, func->end_ea, FC_NOEXT);

  size_t index = 0;
  for (const auto& block : fchart.blocks) {
    this->block_heads.emplace(block.start_ea);
    this->block_types.try_emplace(block.start_ea,
                                  fchart.calc_block_type(index));
    this->block_ends[block.start_ea] = block.end_ea;
    ++index;
  }

  if (get_fileregion_offset(start) == -1) {
    this->in_file = false;
  }
}

void FuncChunk::AddEdge(ea_t source_addr, ea_t dest_addr, EdgeType edge_type) {
  // If this is a fake chunk, we want to keep the target in the list of
  // potential heads. It may not be correct, but we have no way of finding it
  // right now.
  if (this->fake_chunk) {
    auto result = this->block_heads.find(dest_addr);
    if (result == this->block_heads.end()) {
      this->block_heads.emplace(dest_addr);
    }
  }

  this->pending_edges.emplace_back(edge_type, source_addr, dest_addr);
}

std::shared_ptr<Block> FuncChunk::GetBlockContainingAddress(ea_t addr) {
  /*
        auto it = std::lower_bound(blocks.begin(), blocks.end(), addr,
                [](const Block* lhs, const ea_t addr) -> bool {
           return lhs->start_addr < addr;
        });
    */

  auto it = std::find_if(blocks.begin(), blocks.end(),
                         [addr](const std::shared_ptr<Block>& b) -> bool {
                           return b->IsBetween(addr);
                         });

  if (it != blocks.end() && (*it)->IsBetween(addr)) {
    return *it;
  }
  return nullptr;
}

std::optional<int> FuncChunk::GetBlockIdx(
    const std::shared_ptr<Block>& block) const {
  auto it = std::find_if(
      this->blocks.begin(), this->blocks.end(),
      [block](const std::shared_ptr<Block>& b) -> bool { return b == block; });

  if (it != this->blocks.end()) {
    return static_cast<int>(std::distance(this->blocks.begin(), it));
  }

  return std::nullopt;
}

bool FuncChunk::operator<(const FuncChunk& rhs) const {
  return start_addr < rhs.start_addr;
}

bool FuncChunk::operator>(const FuncChunk& rhs) const { return rhs < *this; }

bool FuncChunk::operator<=(const FuncChunk& rhs) const {
  return this->start_addr <= rhs.start_addr;
}

bool FuncChunk::operator>=(const FuncChunk& rhs) const { return rhs <= *this; }

void FuncChunk::Resize(ea_t endaddr) {
  ea_t end = 0;
  for (const auto& block_p : this->blocks) {
    end = std::max(block_p->end_addr, end);
  }

  // For empty chunks, set a size of 1
  if (this->blocks.empty()) {
    this->end_addr = this->start_addr + 1;
    return;
  }

  if (end == 0 or end == BADADDR) {
    QLOGE << "Error while computing end address for chunk";
  }

  this->end_addr = end;
}

Function::Function(func_t* func_p) {
  this->start_addr = func_p->start_ea;

  // Get function name (not mangled)
  this->name = GetName(func_p->start_ea, false);

  // Get the mangled function name, store it only if different
  std::string mangled_name = GetName(func_p->start_ea, true);
  if (mangled_name != this->name)
    this->mangled_name = std::move(mangled_name);

  if (func_p->flags & FUNC_THUNK) {
    this->func_type = TYPE_THUNK;
  } else if (func_p->flags & FUNC_LIB) {
    this->func_type = TYPE_LIBRARY;
  }
}

void ExportImportedFunctions(const ImportManager& import_manager,
                             std::vector<Function>& func_list,
                             const FuncChunkCollection& chunks) {
  for (auto const& [address, import] : import_manager.imports) {
    auto chunk = chunks.GetElement(address, true);
    assert(chunk != nullptr && "An imported function must have a chunk!");
    func_list.emplace_back(address, import.name, chunk);
  }
}

static void ExportFunctionGraph(Function& function, func_t* ida_func,
                                const qflow_chart_t& flow_chart) {
#if IDA_SDK_VERSION < 900
  mutable_graph_t* graph = create_disasm_graph(ida_func->start_ea);
  graph->create_tree_layout();

  // TODO(dm) ASK ida support to export this function
  // graph->create_orthogonal_layout();

  // TODO(dm) If called from command line, the graph is not rendered
  // TODO(dm) ASK Idasupport for a solution
  /*
  if (graph->empty() || flow_chart.blocks.size() != graph->size()) {
      goto next;
  }
  */

  if (graph != nullptr && !graph->empty()) {
    for (int node_idx = 0; node_idx != graph->node_qty(); ++node_idx) {
      rect_t node = graph->nodes[node_idx];

      ea_t node_ea = flow_chart.blocks[node_idx].start_ea;
      if (node_ea == BADADDR) {
        QLOGE << "Node addr is not set";
        continue;
      }

      assert(node_ea - function.start_addr >= 0 &&
             "Negative offset for function chunk");
      function.node_position.insert(
          {Position{CENTER, node.center().x, node.center().y},
           ChunkLocalization(node_ea,
                             function.chunks_index.at(
                                 get_func_chunknum(ida_func, node_ea)))});
    }
  }
#else
  interactive_graph_t* graph = create_disasm_graph(ida_func->start_ea);
  graph->create_tree_layout();

  // TODO(dm) ASK ida support to export this function
  // graph->create_orthogonal_layout();

  // TODO(dm) If called from command line, the graph is not rendered
  // TODO(dm) ASK Idasupport for a solution
  /*
  if (graph->empty() || flow_chart.blocks.size() != graph->size()) {
      goto next;
  }
  */

  if (graph != nullptr && !graph->empty()) {
    for (int node_idx = 0; node_idx != graph->node_qty(); ++node_idx) {
      rect_t node = graph->nodes[node_idx];

      ea_t node_ea = flow_chart.blocks[node_idx].start_ea;
      if (node_ea == BADADDR) {
        QLOGE << "Node addr is not set";
        continue;
      }

      assert(node_ea - function.start_addr >= 0 &&
             "Negative offset for function chunk");
      function.node_position.insert(
          {Position{CENTER, node.center().x, node.center().y},
           ChunkLocalization(node_ea,
                             function.chunks_index.at(
                                 get_func_chunknum(ida_func, node_ea)))});
    }
  }
#endif
}

void ExportFunctions(std::vector<Function>& func_list,
                     FuncChunkCollection& chunks,
                     ImportManager& import_manager) {
  /* Allocate enough space from the start */
  func_list.reserve(get_func_qty());

  Comments& comments = Comments::GetInstance();

  /* Sort collection to improve performance */
  chunks.Sort();

  /**
   * We want to iterate over every function in the binary.
   * However, in some cases, the first function is at address 0 which is also
   * the min_ea. Thus, we first check if there is a function at min_ea and if
   * not, we get the next one.
   */
  ea_t begin_addr = inf_get_min_ea();
  func_t* func = get_func(begin_addr);
  if (func == nullptr) {
    func = get_next_func(begin_addr);
  }

  bool has_exported_imports = false;
  for (; func != nullptr; func = get_next_func(func->start_ea)) {
    if (!is_func_entry(func))
      continue;

    auto function = Function(func);

    qflow_chart_t flow_chart("", func, func->start_ea, func->end_ea, FC_NOEXT);

    if (function.func_type == TYPE_NONE) {
      if (flow_chart.blocks.empty()) {
        function.func_type = TYPE_IMPORTED;
      } else {
        function.func_type = TYPE_NORMAL;
      }
    }

    // Export also comments
    GetFunctionComments(comments, func, std::make_shared<Function>(function));

    // We search the chunk for the head !
    std::shared_ptr<FuncChunk> chunk = chunks.GetElement(func->start_ea, true);
    if (chunk == nullptr) {
      QLOGE << "Unable to retrieve chunk for the head";
      continue;
    }

    assert(get_func_chunknum(func, func->start_ea) == 0 &&
           "Head must be 0 index");

    function.chunks_index[0] = chunk;

    // Iterate through the tails
    func_tail_iterator_t fti(func);
    for (bool ok = fti.first(); ok; ok = fti.next()) {
      const range_t& range = fti.chunk();
      std::shared_ptr<FuncChunk> tail = chunks.GetElement(range.start_ea, true);
      if (tail == nullptr) {
        QLOGE << "Unable to find the chunk";
        continue;
      }

      int chunk_idx = get_func_chunknum(func, range.start_ea);
      function.chunks_index[chunk_idx] = tail;

      std::vector<ea_t> code_refs;
      GetCodeRefFrom(code_refs, range.start_ea);

      for (const auto ref : code_refs) {
        int source_idx = get_func_chunknum(func, ref);
        if (source_idx != -1) {
          function.edges.push_back(
              CreateChunkEdge(TYPE_UNCONDITIONAL, chunks.GetElement(ref, false),
                              ref, tail, range.start_ea));
        }
      }
    }

    // If we have a thunk, it may be hard afterwards to detect the target
    // of the thunk function, so get it from here.
    // For most architecture, the call will already be identified to the
    // last instruction of the thunk (e.g. for ARM64, x86). However, in
    // ARM, we may have the pattern of ADD in PC. So we add the call here.
    // It will be deduplicated when the references will be sorted afterwards.
    if (function.func_type == TYPE_THUNK) {
      ea_t indirect_jump = BADADDR;
      ea_t target = calc_thunk_func_target(func, &indirect_jump);
      if (indirect_jump == BADADDR) {
        const std::shared_ptr<Block> block = chunk->blocks.back();
        ReferenceHolder::GetInstance().emplace_back(
            InstructionInstance(chunk, block, block->instructions.size() - 1),
            target, REF_CALL);
      }
    }

    ExportFunctionGraph(function, func, flow_chart);

    /**
     * Check if the imports function are already exported
     * This is the case for ELF file but not PE
     */
    if (import_manager.IsImport(function.start_addr)) {
      function.func_type = TYPE_IMPORTED;
      has_exported_imports = true;
    }

    func_list.push_back(function);
  }

  if (not has_exported_imports) {
    ExportImportedFunctions(import_manager, func_list, chunks);
  }

  // We need to update every chunk edge and node position to retrieve the block
  // pointed So far, we have a tuple {chunk_idx, addr} and we need to transform
  // to {chunk_idx, block_idx}
  for (Function& function_ : func_list) {
    for (ChunkEdge& chunk_edge : function_.edges) {
      auto source_block_idx =
          chunk_edge.source.chunk->BlockIdxFromAddr(chunk_edge.source.addr);
      auto destination_block_idx =
          chunk_edge.destination.chunk->BlockIdxFromAddr(
              chunk_edge.destination.addr);

      if (source_block_idx != std::nullopt &&
          destination_block_idx != std::nullopt) {
        chunk_edge.source.block_idx = source_block_idx.value();
        chunk_edge.destination.block_idx = destination_block_idx.value();
      } else {
        QLOGE << "Unable to resolve Chunk";
      }
    }

    for (auto& [position, chunk_localisation] : function_.node_position) {
      if (auto block_idx = chunk_localisation.chunk->BlockIdxFromAddr(
              chunk_localisation.addr)) {
        chunk_localisation.block_idx = block_idx.value();
      }
    }
  }
}

void FuncChunkCollection::Sort() {
  if (!sorted) {
    std::sort(this->chunks_.begin(), this->chunks_.end(),
              [](const std::shared_ptr<FuncChunk>& c,
                 const std::shared_ptr<FuncChunk>& d) -> bool {
                return c->start_addr < d->start_addr;
              });
    sorted = true;
  }
}

std::shared_ptr<FuncChunk> FuncChunkCollection::GetElement(
    ea_t addr, bool head_address) const {
  assert(sorted && "The collection must be sorted before using this method");
  auto it =
      std::lower_bound(this->chunks_.begin(), this->chunks_.end(), addr,
                       [](const std::shared_ptr<FuncChunk>& f,
                          ea_t val) -> bool { return f->end_addr <= val; });

  if (it == this->chunks_.end() || not(*it)->InChunk(addr)) {
    return nullptr;
  }

  if (head_address && it->get()->start_addr != addr) {
    return nullptr;
  }
  return *it;
}
}  // namespace quokka
