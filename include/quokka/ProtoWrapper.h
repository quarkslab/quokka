// Copyright 2022 Quarkslab
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
 * @file ProtoWrapper.h
 * Include wrapper around the protobuf to disable certain warnings
 *
 * Solution from https://stackoverflow.com/a/57623557/15051501
 */

#ifndef PROTO_WRAPPER_H
#define PROTO_WRAPPER_H

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4018 4100 4267)
#endif

#include "quokka.pb.h"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif  // PROTO_WRAPPER_H
