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
 * @file Reference.h
 * Management of references
 */

#ifndef QUOKKA_REFERENCE_H
#define QUOKKA_REFERENCE_H

#include <cstdint>
#include <memory>
#include <utility>
#include <variant>
#include <vector>

#include "Compatibility.h"
#include <pro.h>
#include <bytes.hpp>
#include <funcs.hpp>
#include <ida.hpp>
#include <xref.hpp>

#include "absl/hash/hash.h"

#include "Localization.h"  //Kept for Location
#include "Util.h"          //Kept for BucketNew
#include "Windows.h"

namespace quokka {

class Block;
class Data;
class Structures;
class Structure;
enum StructureType : short;
struct StructureMember;
class FuncChunkCollection;
class Instruction;
class FuncChunk;

/**
 * Reference type
 */
enum ReferenceType : short {
  REF_FLOW = 0,
  REF_CALL,  ///< Code reference
  REF_DATA,
  REF_ENUM,
  REF_STRUC,    ///< Data reference
  REF_INVALID,  ///< Invalid
};

/**
 * ---------------------------------------------
 * quokka::Reference
 * ---------------------------------------------
 * Represent a reference
 *
 * A reference is a link between two elements
 * They have a direction (source to destination)
 */
struct Reference {
  Location source_;       ///< Source of the reference
  Location destination_;  ///< Destination
  ReferenceType type;     ///< Type of reference

  /**
   * Constructor
   * @param source Source
   * @param destination Destination
   * @param ref_type Reference type
   */
  Reference(Location source, Location destination, ReferenceType ref_type)
      : source_(std::move(source)),
        destination_(std::move(destination)),
        type(ref_type){};

  /**
   * Hash implementation of the object using absl::Hash
   * @tparam H Hash
   * @param h Hash value
   * @param m Reference object
   * @return An hash value for the object
   */
  template <typename H>
  friend H AbslHashValue(H h, const Reference& m) {
    return H::combine(std::move(h), m.source_, m.destination_, m.type);
  }
};

/**
 * ---------------------------------------------
 * quokka::ReferenceHolder
 * ---------------------------------------------
 * Collection holding every reference found in the binary
 */
class ReferenceHolder {
 private:
  /**
   * Private constructor
   */
  explicit ReferenceHolder() = default;

  /**
   * Map between address and data pointers
   */
  absl::flat_hash_map<ea_t, std::shared_ptr<Data>> data_addresses = {};

  /**
   * References collection
   */
  std::vector<Reference> references = {};

 public:
  /**
   * Singleton pattern
   * @return ReferenceHolder instance
   */
  static ReferenceHolder& GetInstance() {
    static ReferenceHolder instance;
    return instance;
  }

  /**
   * Deleted methods for singleton pattern
   */
  ReferenceHolder(ReferenceHolder const&) = delete;  // Don't implement
  void operator=(ReferenceHolder const&) = delete;   // Don't implement

  /**
   * Emplace a reference to the list of references
   * @tparam Args Arguments
   * @param args Arguments
   * @return A reference
   */
  template <typename... Args>
  Reference& emplace_back(Args&&... args) {
    return this->references.emplace_back(std::forward<Args>(args)...);
  }

  /**
   * Convert an address for a data to a Location element
   *
   * For performances reasons, we already converted every Data to a
   * Location and stored this information in data_addresses
   *
   * @param addr Address to search
   * @param data_bucket Data bucket
   * @return
   */
  Location ResolveData(ea_t addr, const BucketNew<Data>& data_bucket);

  /**
   * Resolve the location
   *
   * If the location argument holds an address, it will be converted to a
   * proper location value.
   *
   * @param location Location to convert
   * @param instructions Instruction bucket
   * @param max_ea Max program ea
   * @param structures Structures collection
   * @param chunks Chunks collections
   * @param data_bucket Data bucket
   * @return A location which does not holds an address anymore
   */
  Location ResolveLocation(Location location,
                           const BucketNew<Instruction>& instructions,
                           ea_t max_ea, const Structures& structures,
                           const FuncChunkCollection& chunks,
                           const BucketNew<Data>& data_bucket);

  /**
   * Iterate through the references, resolve them and remove every invalid
   * reference.
   *
   * A reference is considered invalid if :
   *      - the source is an ea (and its an error)
   *      - the resolved location is an ea
   *      - the reference already exists
   *
   * @param chunks Chunks collections
   * @param instructions Instruction bucket
   * @param data_bucket Data bucket
   * @param structures Structures collection
   */
  void RemoveMissingAddr(const FuncChunkCollection& chunks,
                         const BucketNew<Instruction>& instructions,
                         const BucketNew<Data>& data_bucket,
                         const Structures& structures);

  /**
   * Proxy for size
   * @return size of the references
   */
  [[nodiscard]] std::size_t size() const { return references.size(); }

  /* Iterators proxy */
  using iterator = std::vector<Reference>::iterator;
  using const_iterator = std::vector<Reference>::const_iterator;
  iterator begin() { return references.begin(); }
  iterator end() { return references.end(); }
  [[nodiscard]] const_iterator begin() const { return references.begin(); }
  [[nodiscard]] const_iterator end() const { return references.end(); }
};

/**
 * Resolve edges in chunks or in-between
 *
 * This is a bit more tricky than expected. We have first to check if the
 * block exists (e.g to be in blocks, not in block_heads) to have an inner
 * edge. Otherwise, the choice we made was wrong and the reference is a
 * in fact a *CALL*. So we need to transfer them to the ReferenceHolder.
 *
 * @param chunks Chunks collections
 * @param reference_holder Reference collections
 */
void ResolveEdges(const FuncChunkCollection& chunks,
                  ReferenceHolder& reference_holder);

/**
 * Export the flow graph at `current_ea`
 *
 * This is a bit tricky because it is hard to distinguish normal flow and
 * unconditional jumps
 *
 * @param current_ea Address
 * @param current_chunk Chunks collection
 * @param flow_refs List of flow references
 */
void ExportFlowGraph(ea_t current_ea,
                     const std::shared_ptr<FuncChunk>& current_chunk,
                     const std::vector<ea_t>& flow_refs);

/**
 * Export all code references coming from current_ea
 *
 * @param current_ea Address
 * @param current_chunk Chunks collections
 * @param block_p Current block
 * @param inst_idx Current instruction index
 * @param data_bucket Data bucket
 */
void ExportCodeReference(ea_t current_ea,
                         const std::shared_ptr<FuncChunk>& current_chunk,
                         const std::shared_ptr<Block>& block_p, int inst_idx,
                         BucketNew<Data>& data_bucket);

/**
 * Export all the references towards the data at `current_ea`
 *
 * @param current_ea Address
 * @param data Data
 * @return The number of references found towards this data
 */
uint32_t ExportDataReferences(ea_t current_ea,
                              const std::shared_ptr<Data>& data);

/**
 * Export all the references towards the unknown at current_ea
 *
 * This is a special case from DataReferences has the data does not really
 * exist but will be put in the DataBucket if we find some references towards
 * it (the resulting data will be of size 1 and type UNKNOWN).
 *
 * @param current_ea Address
 * @param data_bucket Data holder
 */
void ExportUnkReferences(ea_t current_ea, BucketNew<Data>& data_bucket);

/**
 * Try to resolve `addr` as a structure Location
 *
 * @param addr Address
 * @param structures Structure collections
 * @return Either a Structure, StructureMember or BADADDR
 */
Location ResolveStructure(ea_t addr, const Structures& structures);

/**
 * Try to resolve addr as a Instruction Instance Location
 *
 * @note `addr` must be less than BADADDR (otherwise it's a structure Location)
 *
 * @param addr Address
 * @param chunks Chunks collection
 * @param instructions Instruction bucket
 * @return BADADDR or InstructionInstance
 */
Location ResolveAddr(ea_t addr, const FuncChunkCollection& chunks,
                     const BucketNew<Instruction>& instructions);

/**
 * Export all references towards this structure
 *
 * @param sid Structure id (actually an address)
 * @param structure Structure
 * @param struct_type Type of structure
 */
void ExportStructureReference(ea_t sid,
                              const std::shared_ptr<Structure>& structure,
                              StructureType struct_type);

/**
 * Export all references towards a structure member
 *
 * @param sid Structure id (actually an address)
 * @param member StructureMember
 * @param struct_type Type of structure
 */
void ExportStructureMemberReference(
    ea_t sid, const std::shared_ptr<StructureMember>& member,
    StructureType struct_type);

/**
 * Compute the type of the code reference
 *
 * @param ref_type Type of reference (fl_ )
 * @param target Target of the reference
 * @param chunk Chunk from the current source
 * @return A reference type
 */
ReferenceType GetCodeRefType(uchar ref_type, ea_t target,
                             const std::shared_ptr<FuncChunk>& chunk);

/**
 * Compute the type of the data reference
 *
 * @param ref_type Type of reference (dr_)
 * @param target Target of the reference
 * @return Reference type
 */
ReferenceType GetDataRefType(uchar ref_type, ea_t target);

/**
 * Get the code reference from the start address
 *
 * @param code_refs (Out) A list of references
 * @param start_addr Starting address
 */
void GetCodeRefFrom(std::vector<ea_t>& code_refs, ea_t start_addr);

}  // namespace quokka
#endif  // QUOKKA_REFERENCE_H
