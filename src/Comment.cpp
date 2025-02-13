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

#include "quokka/Comment.h"

#include "quokka/Function.h"
#include "quokka/Instruction.h"

namespace quokka {

int Comments::GetIndice(const std::string& comment) {
  auto [it, inserted] =
      this->comment_strings.try_emplace(comment, this->comment_strings.size());
  return it->second;
}

void GetRegularComments(Comments& comments, ea_t addr,
                        std::shared_ptr<Instruction>& inst) {
  qstring ida_comment;

  for (bool repeatable : {false, true}) {
    if (get_cmt(&ida_comment, addr, repeatable) > 0) {
      comments.insert(ConvertIdaString(ida_comment), Location(inst),
                      INSTRUCTION);
    }
  }
}

bool GetLineComment(ea_t addr, int index, std::string* output) {
  qstring ida_comment;
  ssize_t result = get_extra_cmt(&ida_comment, addr, index);
  *output = ConvertIdaString(ida_comment);

  return result >= 0;
}

void GetLineComments(Comments& comments, ea_t addr,
                     std::shared_ptr<Instruction>& inst) {
  std::string buffer;

  for (int index : {E_PREV, E_NEXT}) {
    for (int i = 0; GetLineComment(addr, index + i, &buffer); ++i) {
      if (!buffer.empty()) {
        comments.insert(buffer, Location(inst), INSTRUCTION);
      }
      buffer.clear();
    }
  }
}

void GetComments(ea_t addr, std::shared_ptr<Instruction>& inst) {
  Comments& comments = Comments::GetInstance();

  GetRegularComments(comments, addr, inst);
  GetLineComments(comments, addr, inst);
}

void GetFunctionComments(Comments& comments, const func_t* func,
                         std::shared_ptr<Function> function_p) {
  qstring ida_comment;
  for (bool repeatable : {false, true}) {
    if (get_func_cmt(&ida_comment, func, repeatable) > 0) {
      comments.insert(ConvertIdaString(ida_comment), Location(function_p),
                      FUNCTION);
    }
  }
}

}  // namespace quokka

// Additional IDA version specific code
#if IDA_SDK_VERSION < 900
#include "api_v8/Comment.cpp"
#else
#include "api_v9/Comment.cpp"
#endif