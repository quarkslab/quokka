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
 * @file Function.h
 * Management of functions, function chunks and edges
 */

#ifndef QUOKKA_FUNCTION_H
#define QUOKKA_FUNCTION_H

#include <unordered_map>
#include <utility>
#include <vector>

#include "Compatibility.h"
#include <pro.h>
#include <funcs.hpp>
#include <gdl.hpp>
#include <graph.hpp>
#include <loader.hpp>
#ifdef HAS_HEXRAYS
#include <hexrays.hpp>
#endif

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_format.h"

#include "Logger.h"
#include "Windows.h"

namespace quokka {

class Block;

/**
 * Function type
 */
enum FunctionType : short {
  TYPE_NONE = 0,
  TYPE_NORMAL,
  TYPE_IMPORTED,
  TYPE_LIBRARY,
  TYPE_THUNK
};

/**
 * Edge type
 * Used only for CFG export
 */
enum EdgeType : short {
  EDGE_UNK = 0,
  TYPE_UNCONDITIONAL = 1,
  TYPE_TRUE,
  TYPE_FALSE,
  TYPE_SWITCH
};

/**
 * -----------------------------------------------------------------------------
 * quokka::Edge
 * -----------------------------------------------------------------------------
 * Represent an edge in a CFG.
 *
 * They live inside function chunks so their source and destination can be
 * represented with only the block index.
 *
 * @note All edges are directed (from source to destination)
 */
struct Edge {
  /**
   * Constructor
   *
   * @param type Type of edge
   * @param source_block Source block
   * @param dest_block Destination block
   */
  Edge(EdgeType type, int source_block, int dest_block)
      : edge_type(type),
        source_idx(source_block),
        destination_idx(dest_block){};

  EdgeType edge_type;   ///< Type of edge
  int source_idx;       ///< Index of the source block
  int destination_idx;  ///< Index of the destination block
};

/**
 * -----------------------------------------------------------------------------
 * quokka::PendingEdge
 * -----------------------------------------------------------------------------
 * Represent a future edge in the CFG
 *
 * This type of edges is used when we don't know yet the source or destination
 * block so only the address are stored. Every of the pending edges is
 * expected to disappear after the whole program has been analyzed and each
 * address translated to a block index or a call reference.
 */
struct PendingEdge {
  EdgeType edge_type;  ///< Type of edge
  ea_t source;         ///< Source of the edge
  ea_t destination;    ///< Destination of the edge

  /**
   * Constructor
   * @param edge_type Edge type
   * @param source Source
   * @param destination Destination
   */
  PendingEdge(EdgeType edge_type, ea_t source, ea_t destination)
      : edge_type(edge_type), source(source), destination(destination){};
};

class FuncChunk;

/**
 * ---------------------------------------------
 * quokka::ChunkLocalization
 * ---------------------------------------------
 * Location of a chunk
 *
 * At first, the block may not be known so it will be populated afterwards
 */
struct ChunkLocalization {
  ea_t addr = BADADDR;               ///< Address of the target
  std::shared_ptr<FuncChunk> chunk;  ///< Chunk
  int block_idx = -1;                ///< Block index

  /**
   * Constructor used when no block index is known
   *
   * @param addr_ Target address
   * @param chunk_p Chunk
   */
  ChunkLocalization(ea_t addr_, std::shared_ptr<FuncChunk> chunk_p)
      : addr(addr_), chunk(std::move(chunk_p)), block_idx(-1) {}

  /**
   * Complete constructor
   *
   * @param addr_ Target address
   * @param chunk_p Chunk
   * @param block Block index
   */
  ChunkLocalization(ea_t addr_, std::shared_ptr<FuncChunk> chunk_p, int block)
      : addr(addr_), chunk(std::move(chunk_p)), block_idx(block) {}
};

/**
 * ---------------------------------------------
 * quokka::ChunkEdge
 * ---------------------------------------------
 * Edge between two chunks
 *
 * This type of edges are used in a function reconstruction and are directed.
 */
struct ChunkEdge {
  EdgeType edge_type = EdgeType::EDGE_UNK;  ///< Type of edge
  ChunkLocalization source;                 ///< Source chunk
  ChunkLocalization destination;            ///< Destination chunk
};

/**
 * Type of block position coordinates
 *
 * When the CFG layout is exported, we also keep the position (x,y) of each
 * block. It's either the top left point or the block center that is stored.
 */
enum PositionType : short { CENTER = 0, TOP_LEFT };

/**
 * ---------------------------------------------
 * quokka::Position
 * ---------------------------------------------
 * Block position in the graph layout
 *
 * We try to export the layout of the graph (e.g. how it is represented in
 * IDA GUI) so another tool could directly represent the same graph with the
 * same layout.
 */
struct Position {
  PositionType pos_type;  ///< Where are the coordinates origin
  int64 x;                ///< X point
  int64 y;                ///< Y point

  /**
   * Operator definitation
   * Compare euclidian norm
   */
  bool operator<(const Position& pos) const {
    return pow(x + y, 2) < pow(pos.x + pos.y, 2);
  };

  /**
   * Hash implementation of the object using absl::Hash
   * @tparam H Hash
   * @param h Hash value
   * @param m Position object
   * @return An hash value for the object
   */
  template <typename H>
  friend H AbslHashValue(H h, const Position& m) {
    return H::combine(std::move(h), m.x, m.y, m.pos_type);
  }

  /**
   * Equality operator
   */
  bool operator==(const Position& pos) const {
    return pos.x == x && pos.y == y && pos_type == pos.pos_type;
  }
};

/**
 * ---------------------------------------------
 * quokka::FuncChunk
 * ---------------------------------------------
 * Function chunk representation
 *
 * The definition of a chunk is a sequence of consecutive blocks (may
 * be intervened with data on some arch) which are part of a function. They
 * may not represent a connected graph however.
 *
 * `FuncChunk` in quokka may also be "fake", like blocks. They represent
 * in this case a sequence of blocks. They are used when the function
 * recognition failed and orphaned instructions are found so every
 * instruction belongs to at least one `FuncChunk`.
 */
class FuncChunk {
 public:
  ea_t start_addr = BADADDR;  ///< Start address of the chunk
  ea_t end_addr = BADADDR;    ///< End address

  bool fake_chunk = false;  ///< Is the chunk fake

  /**
   * Is the chunk part of the binary ?
   * Code may be retrieved by IDA for dependency that does not belong to
   * the analyzed program, so we keep here if the chunk correspond to code
   * inside the binary
   */
  bool in_file = true;

  int proto_index = -1;  ///< Index of the chunk in the export file

  /**
   * Set of the block starting address
   */
  absl::flat_hash_set<ea_t> block_heads;

  /**
   * Block types
   */
  absl::flat_hash_map<ea_t, fc_block_type_t> block_types;

  /**
   * Map between the start of blocks and their end address
   */
  absl::flat_hash_map<ea_t, ea_t> block_ends;

  std::vector<std::shared_ptr<Block>> blocks;  ///< List of blocks

  std::vector<Edge> edge_list;             ///< List of edges between blocks
  std::vector<PendingEdge> pending_edges;  ///< List of pending edges

  /**
   * Constructor for fake chunk
   * @param start Starting address
   */
  explicit FuncChunk(ea_t start) : start_addr(start), fake_chunk(true){};

  /**
   * Constructor for fake chunk for imports
   *
   * @param start Starting address
   * @param is_import Is the chunk associated with an imported function?
   */
  explicit FuncChunk(ea_t start, bool is_import)
      : start_addr(start),
        fake_chunk(true),
        end_addr(start + 1),
        in_file(false){};

  /**
   * Constructor for real chunk
   * @param start Starting address
   * @param func IDA func object
   */
  FuncChunk(ea_t start, func_t* func);

  /**
   * Add an edge between two addresses.
   *
   * This will be added to the pending_edges list.
   * @note For fake chunks, it will also consider the destination to be a
   * potential block head.
   *
   * @param source_addr Source address
   * @param dest_addr Destination address
   * @param edge_type Type of edge
   */
  void AddEdge(ea_t source_addr, ea_t dest_addr, EdgeType edge_type);

  /**
   * Check if `addr` belong to the chunk
   * @param addr Start address
   * @return Boolean for success
   */
  [[nodiscard]] bool InChunk(ea_t addr) const {
    return this->start_addr <= addr && addr < this->end_addr;
  };

  /**
   * Retrieve the block index of `block`
   * @param block Block to search
   * @return Positive integer if found
   */
  [[nodiscard]] std::optional<int> GetBlockIdx(
      const std::shared_ptr<Block>& block) const;

  /**
   * Get the block where `addr` belong
   * TODO(dm) keep a sorted list of blocks in the FuncChunk
   * @param addr Address to search
   * @return Pointer to a block
   */
  std::shared_ptr<Block> GetBlockContainingAddress(ea_t addr);

  /**
   * Retrieve the block index from the address
   * TODO(dm) improve perf
   * @param addr Address to search
   * @return Positive index
   */
  std::optional<int> BlockIdxFromAddr(ea_t addr) {
    std::shared_ptr<Block> b = this->GetBlockContainingAddress(addr);
    if (b != nullptr) {
      return GetBlockIdx(b);
    }
    return std::nullopt;
  }

  /**
   * Resize the chunk
   * This set the end address to the max address of any of the blocks in
   * the chunk. Will fail if a block have no end address (or a BADADDR)
   * @param end_addr New end address to check for correctness
   */
  void Resize(ea_t end_addr);

  /**
   * Operator overloading
   */
  bool operator<(const FuncChunk& rhs) const;
  bool operator>(const FuncChunk& rhs) const;
  bool operator<=(const FuncChunk& rhs) const;
  bool operator>=(const FuncChunk& rhs) const;
};

/**
 * ---------------------------------------------
 * quokka::FuncChunkCollection
 * ---------------------------------------------
 * Containers for function chunks
 *
 * Every function chunk will be kept in this container. However, it is not a
 * bucket because Function Chunks are unique.
 */
class FuncChunkCollection {
 private:
  std::vector<std::shared_ptr<FuncChunk>> chunks_;  ///< Container
  bool sorted = false;                              ///< Is the container sorted

 public:
  using iterator = std::vector<std::shared_ptr<FuncChunk>>::iterator;
  using const_iterator =
      std::vector<std::shared_ptr<FuncChunk>>::const_iterator;

  /**
   * Proxy to begin
   * @return
   */
  iterator begin() { return chunks_.begin(); }

  /**
   * Proxy to end
   * @return
   */
  iterator end() { return chunks_.end(); }

  /**
   * Proxy to begin
   * @return
   */
  [[nodiscard]] const_iterator begin() const { return chunks_.begin(); }

  /**
   * Proxy to end
   * @return
   */
  [[nodiscard]] const_iterator end() const { return chunks_.end(); }

  /**
   * Sort the chunk collection
   * The key used is the start address. Sorting the collection improves a
   * lot the performance for a lot of following algorithm
   *
   * TODO(dm) See if it's not possible to keep always the collection sorted ?
   *
   * @return
   */
  void Sort();

  /**
   * Add a new  chunk to the collection
   *
   * @tparam Args Arguments
   * @param args Arguments
   * @return FuncChunk object
   */
  template <typename... Args>
  std::shared_ptr<FuncChunk> Insert(Args&&... args) {
    this->sorted = false;
    this->chunks_.emplace_back(
        std::make_shared<FuncChunk>(std::forward<Args>(args)...));
    return this->chunks_.back();
  }

  /**
   * Retrieve the FuncChunk that contains addr
   *
   * @warning This method expect the collection to be sorted !!
   *
   * @param addr Address to search
   * @param head_address Is the address the starting address of the chunk
   * @return
   */
  [[nodiscard]] std::shared_ptr<FuncChunk> GetElement(ea_t addr,
                                                      bool head_address) const;

  /**
   * Proxy to size
   * @return Collection size
   */
  [[nodiscard]] std::size_t size() const { return this->chunks_.size(); }
};

/**
 * ---------------------------------------------
 * quokka::Function
 * ---------------------------------------------
 * Function representation
 *
 * A function is composed at least from one FunctionChunk.
 */
class Function {
 public:
  ea_t start_addr = BADADDR;  ///< Starting address
  std::string name;           ///< Function name
  std::string mangled_name;   ///< Function mangled name (not empty only if
                              ///< different than the standard one)
  FunctionType func_type = TYPE_NONE;  ///< Function type
  std::string decompiled_code;  ///< Decompiled code (if any)

  int proto_index = -1;  ///< Index in the protobuf

  /**
   * A mapping between IDA-chunk index and function chunks.
   */
  std::unordered_map<int, std::shared_ptr<FuncChunk>> chunks_index;

  /**
   * List of ChunkEdges
   */
  std::vector<ChunkEdge> edges;

  /* Map between the node addr and position */
  /**
   * Mapping between the node position and its chunk localization.
   */
  std::unordered_map<Position, ChunkLocalization, absl::Hash<Position>>
      node_position;

  /**
   * Constructor using a function
   * @param func_p IDA-func
   */
  explicit Function(func_t* func_p);

  Function(ea_t start_, std::string name_, std::shared_ptr<FuncChunk> chunk_)
      : start_addr(start_), name(std::move(name_)), func_type(TYPE_IMPORTED) {
    this->chunks_index[0] = std::move(chunk_);
  };


  void ExportDecompiledFunction(func_t* func_p);
};

/**
 * Create a chunk edge
 *
 * Create an edge between the source and destination
 *
 * @param edge_type Type of edge (always `TYPE_UNCONDITIONAL`)
 * @param source_chunk Source chunk
 * @param source_addr Source address
 * @param dest_chunk Destination chunk
 * @param dest_addr Destination address
 * @return
 */
ChunkEdge CreateChunkEdge(EdgeType edge_type,
                          std::shared_ptr<FuncChunk> source_chunk,
                          ea_t source_addr,
                          std::shared_ptr<FuncChunk> dest_chunk,
                          ea_t dest_addr);

class ImportManager;

/**
 * Export all the functions in the binary
 *
 * @param func_list (out) List of functions
 * @param chunks Chunks collections
 * @param import_manager Import manager
 */
void ExportFunctions(std::vector<Function>& func_list,
                     FuncChunkCollection& chunks,
                     ImportManager& import_manager);

/**
 * Exported imported function
 *
 * This function is only called when they are not exported by default.
 *
 * @param import_manager Import Manager
 * @param func_list  List of functions
 * @param chunks Chunk collection*
 */
void ExportImportedFunctions(const ImportManager& import_manager,
                             std::vector<Function>& func_list,
                             const FuncChunkCollection& chunks);

}  // namespace quokka
#endif  // QUOKKA_FUNCTION_H
