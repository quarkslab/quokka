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
 * @file Quokka.h
 * Plugin definition
 *
 * Handle all the plugin management (arguments, starts, registration)
 */

#ifndef QUOKKA_H
#define QUOKKA_H

#include <filesystem>
#include <fstream>
#include <string>

#include <auto.hpp>
#include <entry.hpp>
#include <expr.hpp>
#include <gdl.hpp>
#include <graph.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <nalt.hpp>

#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"

#include "Windows.h"

#include "ProtoWrapper.h"

namespace quokka {

enum ExporterMode : short;

/**
 * Retrieve the export mode by looking at the argument passed on the command
 * line
 *
 * @return The correct export mode. By default it is MODE_NORMAL
 */
ExporterMode GetModeFromArgument();

/**
 * Retrieve the argument passed on the command line
 *
 * An option may be passed to a plugin using the -O{PluginName}{Option}={Value}
 *
 * @param name Name of the argument
 * @param to_upper Should we convert the value to upper case ?
 * @return
 */
std::string GetArgument(const char* name, bool to_upper = false);

/**
 * Return an output filename
 *
 * First try to see if the option "File" as been set.
 * Then try to store it in the same directory as input file using "
 * .Quokka" extension
 *
 * @return A potential output file name
 */
std::string GetOutputFileName();

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
 * Export the binary to filename
 *
 * Here we are ! Main method of the plugin, will take care of export the
 * loaded binary.
 *
 * @note If the filename is not writable, another try will be made in the
 * /tmp directory. However, this will not works on Windows.
 *
 * @return Code for success
 */
int ExportBinary(const std::string& filename);

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
