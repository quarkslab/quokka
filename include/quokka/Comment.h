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
 * @file Comment.h
 * Management of comments.
 */

#ifndef QUOKKA_COMMENT_H
#define QUOKKA_COMMENT_H

#include <string>
#include <utility>
#include <vector>

#include "Compatibility.h"
#include <bytes.hpp>
#include <enum.hpp>
#include <funcs.hpp>
#include <ida.hpp>
#include <struct.hpp>

#include "absl/container/flat_hash_map.h"

#include "Localization.h"  //Kept for Location
#include "Util.h"
#include "Windows.h"


namespace quokka {

class Instruction;
class Structure;
class Function;
struct StructureMember;

/**
 * Type of comments.
 * These values are used to associate the comment with its location. An
 * address may have multiple comments attached to different "locations".
 */
enum CommentType : short {
  INSTRUCTION = 0,
  FUNCTION,
  STRUCTURE,
};

/**
 * -----------------------------------------------------------------------------
 * quokka::Comment
 * -----------------------------------------------------------------------------
 * A single comment structure.
 */
struct Comment {
  int indice;        ///< Index of the comment in the `Comments.comment_strings`
  CommentType type;  ///< Type of the comment

  Location location;  ///< Where to attach the comment

  /**
   * Construct a comment.
   *
   * @param indice_ Index of the comment string in the Comments container.
   * @param location_ Where to attach the comment
   * @param type_ Type of the comment
   */
  Comment(int indice_, Location location_, CommentType type_)
      : location(std::move(location_)), indice(indice_), type(type_) {}
};

/**
 * -----------------------------------------------------------------------------
 * quokka::Comments
 * -----------------------------------------------------------------------------
 * Container for all the comments found in the disassembly.
 */
class Comments {
 private:
  /**
   * Map between the value of the comment and its index.
   * Comments string are stored in a deduplicated list and only the index
   * of the string in this list is stored.
   */
  absl::flat_hash_map<std::string, int> comment_strings;

  std::vector<Comment> comments;  ///< List of all comments

  /**
   * Constructor.
   * Kept private for the singleton pattern.
   */
  explicit Comments() = default;

 public:
  /**
   * Return the instance of the `Comments` class.
   * Used for the singleton pattern.
   * @return `Comments`
   */
  static Comments& GetInstance() {
    static Comments instance;
    return instance;
  }

  /**
   * Deleted constructors for singleton pattern
   */
  Comments(Comments const&) = delete;
  void operator=(Comments const&) = delete;

  /**
   * Retrieve the index of the `comment` string.
   *
   * If the comment string is not already present in the list of comments
   * string, add it.
   *
   * @param comment Comment string to search
   * @return A positive integer representing the index
   */
  int GetIndice(const std::string& comment);

  /**
   * Insert a comment in the comments list.
   *
   * Add the string value to the deduplicated list and create a structure
   * with the index.
   *
   * @tparam Args The remaining arguments of the Comment constructor
   * @param comment Comment string
   * @param args Remaining arguments of the Comment constructor
   * @return The new `Comment`
   */
  template <typename... Args>
  Comment& insert(const std::string& comment, Args&&... args) {
    int comment_indice = this->GetIndice(comment);
    this->comments.emplace_back(comment_indice, std::forward<Args>(args)...);
    return this->comments.back();
  }

  /**
   * Accessor for `comments`
   * @return The list of comments stored
   */
  [[nodiscard]] const std::vector<Comment>& GetComments() const {
    return comments;
  }

  /**
   * Accessor for the `comment_strings`.
   * @return The list of stored strings
   */
  [[nodiscard]] const absl::flat_hash_map<std::string, int>& GetCommentStrings()
      const {
    return comment_strings;
  }
};

/**
 * Retrieve regular comments attached to an instruction if any are found.
 *
 * Searches for both repeatable and non repeatable comments.
 *
 * @param comments The comments container
 * @param addr Address to look at
 * @param inst Instruction to attach the comment
 */
void GetRegularComments(Comments& comments, ea_t addr,
                        std::shared_ptr<Instruction>& inst);

/**
 * Retrieve the list of comments that may be attached to the address of an
 * instruction.
 *
 * @see GetLineComments
 * @see GetRegularComments
 *
 * @param addr Address to look at
 * @param inst Instruction to attach the comment
 */
void GetComments(ea_t addr, std::shared_ptr<Instruction>& inst);

/**
 * Retrieve all the extra comment of `addr`.
 *
 * @param comments The comments container
 * @param addr Address to look at
 * @param inst Instruction to attach the comment
 */
void GetLineComments(Comments& comments, ea_t addr,
                     std::shared_ptr<Instruction>& inst);

/**
 * Retrieve the extra comment at `index`.
 *
 * @param addr Address to look at
 * @param index Index to look at
 * @param output Value of the comment retrieved
 * @return True if a comment has been found
 */
bool GetLineComment(ea_t addr, int index, std::string* output);

/**
 * Retrieve the comments associated the function `func`
 *
 * Works for both repeatable / non repeatable comments.
 *
 * @param comments Comments container
 * @param func A pointer to the `func_t` object (IDA)
 * @param function_p A pointer to the `quokka::Function` object
 */
void GetFunctionComments(Comments& comments, const func_t* func,
                         std::shared_ptr<Function> function_p);

/**
 * Retrieve the comments associated to the member of an enumeration.
 *
 * @param member_p Pointer to the `quokka::StructureMember`
 * @param member Pointer to the `const_t` (IDA)
 */
void GetEnumMemberComment(std::shared_ptr<StructureMember> member_p,
                          const_t member);

/**
 * Retrieve the comments associated to the enum.
 *
 * @warning Does not retrieve the comments associated to the enum member
 *
 * @param structure A quokka::Structure pointer
 * @param ida_enum The ida enum
 */
void GetEnumComment(std::shared_ptr<Structure> structure, enum_t ida_enum);

/**
 * Retrieve the comments associated to the members of a structure
 *
 * @param member_p Pointer to the `quokka::StructureMember`
 * @param member Pointer to the `tid_t` (IDA)
 */
void GetStructureMemberComment(std::shared_ptr<StructureMember> member_p,
                               tid_t member);

/**
 * Retrieve the comments associated to the structure.
 *
 * @warning Does not retrieve the comments associated to the struct member
 *
 * @param structure A quokka::Structure pointer
 * @param ida_struct The ida struct
 */
void GetStructureComment(std::shared_ptr<Structure> structure,
                         tid_t ida_struct);

}  // namespace quokka
#endif  // QUOKKA_COMMENT_H
