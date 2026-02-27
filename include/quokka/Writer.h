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

#include <deque>
#include <vector>

#include "Bucket.h"
#include "Data.h"
#include "FileMetadata.h"
#include "Function.h"
#include "Layout.h"
#include "ProtoWrapper.h"
#include "Windows.h"

namespace quokka {

// /**
//  * Convert a function type to the proto associated type
//  * @param position_type Type to convert
//  * @return Converted type
//  */
// quokka::Quokka::Function::Position::PositionType ToProtoPositionType(
//     PositionType position_type);

// /**
//  * Convert a function type to the proto associated type
//  * @param comment_type Type to convert
//  * @return Converted type
//  */
// quokka::Quokka::Comment::CommentType ToProtoCommentType(
//     CommentType comment_type);

// /**
//  * Convert a function type to the proto associated type
//  * @param struct_type Type to convert
//  * @return Converted type
//  */
// quokka::Quokka::Structure::StructureType ToProtoStructType(
//     StructureType struct_type);

// /**
//  * Write the mnemonics
//  *
//  * @param proto Main protobuf
//  * @param mnemonics Mnemonics bucket
//  */
// void WriteMnemonic(quokka::Quokka* proto, BucketNew<Mnemonic>& mnemonics);

// /**
//  * Write the operand strings
//  * @param proto Main protobuf
//  * @param operand_strings Operand strings bucket
//  */
// void WriteOperandStrings(quokka::Quokka* proto,
//                          BucketNew<OperandString>& operand_strings);

// /**
//  * Write operands
//  *
//  * @param proto Protobuf main object
//  * @param operands Operands bucket
//  */
// void WriteOperands(quokka::Quokka* proto, BucketNew<Operand>& operands);

// /**
//  * Write instructions
//  *
//  * @param proto Protobuf main object
//  * @param instructions
//  */
// void WriteInstructions(quokka::Quokka* proto,
//                        BucketNew<Instruction>& instructions);

// /**
//  * Write Block identifier
//  *
//  * @param proto_block_id Protobuf object to the block identifier
//  * @param block_idx Block index
//  * @param chunk_idx Chunk index (-1 if not set)
//  */
// void WriteBlockIdentifier(quokka::Quokka::BlockIdentifier* proto_block_id,
//                           int block_idx, int chunk_idx);

// /**
//  * Write inner edges (edges within a chunk)
//  *
//  * @param proto_chunk Protobuf object to the chunk
//  * @param edge_list List of edges
//  */
// void WriteInnerEdges(quokka::Quokka::FunctionChunk* proto_chunk,
//                      const std::vector<Edge>& edge_list);

// /**
//  * Write the function chunks
//  *
//  * @param proto Protobuf main object
//  * @param chunks_list Chunks collection
//  */
// void WriteFuncChunk(quokka::Quokka* proto, FuncChunkCollection& chunks_list);

// /**
//  * Write positions
//  *
//  * @param proto_position Protobuf object position
//  * @param position Position to write
//  */
// void WritePosition(quokka::Quokka::Function::Position* proto_position,
//                    const Position& position);

/**
 * Write the functions
 *
 * @param proto Protobuf main object
 * @param functions Function collections
 */
void WriteFunctions(Quokka* proto, const std::vector<Function>& functions);

/**
 * Write the references
 *
 * @param proto Protobuf main object
 */
void WriteReferences(Quokka* proto);

/**
 * Write data
 *
 * @param proto Protobuf main object
 * @param data_bucket Data bucket
 */
void WriteData(Quokka* proto, SetBucket<Data>& data_bucket);

// /**
//  * Write comments
//  * @param proto Protobuf main object
//  * @param comments Comments collection
//  */
// void WriteComments(quokka::Quokka* proto, Comments* comments);

/**
 * Write metadata
 *
 * @param proto Protobuf main object
 * @param metadata Exported file metadata
 */
void WriteMetadata(Quokka* proto, const Metadata& metadata);

/**
 * Write all the exported types (composite, enums, primitive)
 *
 * @param proto Protobuf main object
 */
void WriteTypes(Quokka* proto);

/**
 * Write all the headers (local types)
 *
 * @param proto Protobuf main object
 */
void WriteHeaders(Quokka* proto);

/**
 * Write the exporter metadata
 *
 * @param proto Protobuf main object
 */
void WriteExporterMeta(Quokka* proto);

/**
 * Write the segments
 *
 * @param proto Protobuf main object
 */
void WriteSegments(Quokka* proto);

/**
 * Write the layouts
 *
 * @param proto Protobuf main object
 * @param layouts Layouts collection
 */
void WriteLayout(Quokka* proto, const std::deque<Layout>& layouts);

}  // namespace quokka

#endif  // QUOKKA_WRITER_H
