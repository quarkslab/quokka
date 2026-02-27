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
 * @file Quokka.h
 * Plugin definition
 *
 * Handle all the plugin management (arguments, starts, registration)
 */

#ifndef QUOKKA_H
#define QUOKKA_H

// #include <fstream>
#include <sys/types.h>
#include <cstdarg>
#include <cstddef>
#include <string>

// clang-format off: Compatibility.h must come before ida headers
#include "Compatibility.h"
// clang-format on
#include <pro.h>
#include <expr.hpp>
#include <idp.hpp>

#include "Settings.h"
#include "Windows.h"

namespace quokka {

/**
 * Function registered to be called via IDC
 */
static error_t idaapi IdcQuokka(idc_value_t*, idc_value_t*);

/**
 * Hook to the main event
 *
 * If the auto parameter has been set, wait for the auto analysis to finish
 * and then export the binary.
 *
 * @param event_id Event id
 * @param arguments Event arguments (Not used)
 * @return Either 0 or exit IDA
 */
ssize_t idaapi UIHook(void*, int event_id, va_list arguments);

/**
 * Unset simplification flag
 * In case of an ARM processor, we don't want IDA to "simplify" the
 * consecutive instruction (e.g. mov) so we disable the flag.
 *
 * @warning There is no known possibility to query the value so we remove it
 * all the time but we don't reset it.
 */
void UnsimplifyARM();

/**
 * Get argument for command line and set Log level
 * Defaults to INFO
 */
void SetLogLevel();

/**
 * Plugin init
 *
 * Set up the register and hook it to the notification point
 *
 * @return True if the plugin inited correctly
 */
bool PluginInit();

/**
 * Plugin run - ida method -
 *
 * Will show a "nice" user interface to select export file.
 */
bool idaapi PluginRun(size_t /* arg */);

/**
 * Unregister the plugin
 */
void idaapi PluginTerminate();

#if IDA_SDK_VERSION >= 750

/**
 * ---------------------------------------------
 * quokka::plugin_ctx_t
 * ---------------------------------------------
 * The plugin context class
 *
 * After SDK 7.5, IDA plugin registration has changed. This class use the new
 * pattern (inheriting from plugmod_t). Every function is however, just a
 * proxy to their previous definition.
 */
struct plugin_ctx_t : public plugmod_t {
  /**
   * Constructor
   * @see quokka::PluginInit
   */
  plugin_ctx_t() { PluginInit(); }

  /**
   * Run the plugin.
   *
   * @see quokka::PluginRun
   *
   * @param args Unused
   * @return Boolean for success
   */
  bool idaapi run(size_t args) override { return PluginRun(args); };

  /**
   * Unregister the plugin
   * @see quokka::PluginTerminate
   */
  ~plugin_ctx_t() override { PluginTerminate(); };
};
#endif

}  // namespace quokka
#endif
