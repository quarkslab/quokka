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
 * @file Writer.h
 * Functions to write the export on the wire
 */

#ifndef QUOKKA_WRITER_H
#define QUOKKA_WRITER_H

#include <cassert>
#include <cstdint>
#include <stdexcept>

#include "Compatibility.h"
#include <pro.h>

#include "absl/container/btree_set.h"
#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"

#include "Localization.h"
#include "Logger.h"
#include "ProtoWrapper.h"
#include "Util.h"
#include "Windows.h"

namespace quokka {

class Operand;
struct Position;

class Mnemonic;
class OperandString;
class Instruction;
class Data;
class Structure;
struct StructureMember;
class Function;
class FuncChunk;
class Block;
class Function;
struct Edge;
class FuncChunkCollection;
class Structures;
struct Segment;
struct Layout;
class Metadata;
class ReferenceHolder;
class Comments;

enum DataType : short;
enum CommentType : short;
enum ProcName : short;
enum AddressSize : short;
enum CallingConvention : short;
enum Compiler : short;
enum HashType : short;
enum Endianness : short;
enum StructureType : short;
enum SegmentType : short;
enum BlockType : short;
enum FunctionType : short;
enum PositionType : short;
enum ReferenceType : short;
enum State : short;
enum ExporterMode : short;

/**
 * Convert a function type to the proto associated type
 * @param func_type Type to convert
 * @return Converted type
 */
quokka::Quokka::Function::FunctionType ToProtoFuncType(FunctionType func_type);

/**
 * Convert a function type to the proto associated type
 * @param position_type Type to convert
 * @return Converted type
 */
quokka::Quokka::Function::Position::PositionType ToProtoPositionType(
    PositionType position_type);

/**
 * Convert a function type to the proto associated type
 * @param ref_type Type to convert
 * @return Converted type
 */
quokka::Quokka::Reference::ReferenceType ToProtoReferenceType(
    ReferenceType ref_type);

/**
 * Convert a function type to the proto associated type
 * @param data_type Type to convert
 * @return Converted type
 */
quokka::Quokka::DataType ToProtoDataType(DataType data_type);

/**
 * Convert a function type to the proto associated type
 * @param comment_type Type to convert
 * @return Converted type
 */
quokka::Quokka::Comment::CommentType ToProtoCommentType(
    CommentType comment_type);

/**
 * Convert a function type to the proto associated type
 * @param proc_name Type to convert
 * @return Converted type
 */
quokka::Quokka::Meta::ISA ToProtoIsa(ProcName proc_name);

/**
 * Convert a function type to the proto associated type
 * @param endianness Type to convert
 * @return Converted type
 */
quokka::Quokka::Meta::Endianess ToProtoEndianness(Endianness endianness);

/**
 * Convert a function type to the proto associated type
 * @param addr_size Type to convert
 * @return Converted type
 */
quokka::Quokka::AddressSize ToProtoAddressSize(AddressSize addr_size);

/**
 * Convert a function type to the proto associated type
 * @param compiler_type Type to convert
 * @return Converted type
 */
quokka::Quokka::Meta::Compiler ToProtoCompiler(Compiler compiler_type);

/**
 * Convert a function type to the proto associated type
 * @param cc Type to convert
 * @return Converted type
 */
quokka::Quokka::Meta::CallingConvention ToProtoCallingConvention(
    CallingConvention cc);

/**
 * Convert a function type to the proto associated type
 * @param hash_type Type to convert
 * @return Converted type
 */
quokka::Quokka::Meta::Hash::HashType ToProtoHashType(HashType hash_type);

/**
 * Convert a function type to the proto associated type
 * @param struct_type Type to convert
 * @return Converted type
 */
quokka::Quokka::Structure::StructureType ToProtoStructType(
    StructureType struct_type);

/**
 * Convert a function type to the proto associated type
 * @param state Type to convert
 * @return Converted type
 */
quokka::Quokka::Layout::LayoutType GetLayoutTypeByState(State state);

/**
 * Convert a function type to the proto associated type
 * @param type Type to convert
 * @return Converted type
 */
quokka::Quokka::Segment::Type ToProtoSegmentType(SegmentType type);

/**
 * Write the mnemonics
 *
 * @param proto Main protobuf
 * @param mnemonics Mnemonics bucket
 */
void WriteMnemonic(quokka::Quokka* proto, BucketNew<Mnemonic>& mnemonics);

/**
 * Write the operand strings
 * @param proto Main protobuf
 * @param operand_strings Operand strings bucket
 */
void WriteOperandStrings(quokka::Quokka* proto,
                         BucketNew<OperandString>& operand_strings);

/**
 * Write operands
 *
 * @param proto Protobuf main object
 * @param operands Operands bucket
 */
void WriteOperands(quokka::Quokka* proto, BucketNew<Operand>& operands);

/**
 * Write instructions
 *
 * @param proto Protobuf main object
 * @param instructions
 */
void WriteInstructions(quokka::Quokka* proto,
                       BucketNew<Instruction>& instructions);

/**
 * Convert a block type type to the proto associated type
 * @param block_type Type to convert
 * @return
 */
quokka::Quokka::FunctionChunk::Block::BlockType ToProtoBlockType(
    BlockType block_type);

/**
 * Convert a mode to the proto associated type
 * @param mode Type to convert
 * @return
 */
quokka::Quokka::ExporterMeta::Mode ToProtoModeType(ExporterMode mode);

/**
 * Write blocks
 *
 * @param proto_chunk Current protobuf object for FunctionChunk
 * @param block Block to write
 * @param base_addr Base address (@see get_imagebase)
 */
void WriteBlock(quokka::Quokka::FunctionChunk* proto_chunk,
                const std::shared_ptr<Block>& block, ea_t base_addr);

/**
 * Write Block identifier
 *
 * @param proto_block_id Protobuf object to the block identifier
 * @param block_idx Block index
 * @param chunk_idx Chunk index (-1 if not set)
 */
void WriteBlockIdentifier(quokka::Quokka::BlockIdentifier* proto_block_id,
                          int block_idx, int chunk_idx);

/**
 * Write inner edges (edges within a chunk)
 *
 * @param proto_chunk Protobuf object to the chunk
 * @param edge_list List of edges
 */
void WriteInnerEdges(quokka::Quokka::FunctionChunk* proto_chunk,
                     const std::vector<Edge>& edge_list);

/**
 * Write the function chunks
 *
 * @param proto Protobuf main object
 * @param chunks_list Chunks collection
 */
void WriteFuncChunk(quokka::Quokka* proto, FuncChunkCollection& chunks_list);

/**
 * Write positions
 *
 * @param proto_position Protobuf object position
 * @param position Position to write
 */
void WritePosition(quokka::Quokka::Function::Position* proto_position,
                   const Position& position);

/**
 * Write the functions
 *
 * @param proto Protobuf main object
 * @param func_list Function collections
 * @param chunk_map Chunks collection
 */
void WriteFunctions(quokka::Quokka* proto, std::vector<Function>& func_list,
                    const FuncChunkCollection& chunk_map);

/**
 * Write location element
 *
 * @param proto_location Protobuf object location
 * @param location Location to write
 */
void WriteLocation(quokka::Quokka::Location* proto_location,
                   const Location& location);

/**
 * Write the references
 *
 * @param proto Protobuf main object
 * @param ref_holder References collection
 */
void WriteReferences(quokka::Quokka* proto, const ReferenceHolder& ref_holder);

/**
 * Write data
 *
 * @param proto Protobuf main object
 * @param data_bucket Data bucket
 */
void WriteData(quokka::Quokka* proto, BucketNew<Data>& data_bucket);

/**
 * Write comments
 * @param proto Protobuf main object
 * @param comments Comments collection
 */
void WriteComments(quokka::Quokka* proto, Comments* comments);

/**
 * Write metadata
 *
 * @param proto Protobuf main object
 * @param metadata Exported file metadata
 */
void WriteMetadata(quokka::Quokka* proto, const Metadata& metadata);

/**
 * Write the structure
 *
 * @param proto Protobuf main object
 * @param structures Structures collection
 */
void WriteStructures(quokka::Quokka* proto, Structures& structures);

/**
 * Write the exporter metadata
 *
 * @param proto Protobuf main object
 */
void WriteExporterMeta(quokka::Quokka* proto);

/**
 * Write the segments
 *
 * @param proto Protobuf main object
 * @param segments Segments collections
 */
void WriteSegments(quokka::Quokka* proto, const std::vector<Segment>& segments);

/**
 * Write the layouts
 *
 * @param proto Protobuf main object
 * @param layouts Layouts collection
 */
void WriteLayout(quokka::Quokka* proto, const std::deque<Layout>& layouts);

}  // namespace quokka

#endif  // QUOKKA_WRITER_H
