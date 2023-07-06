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

#include "quokka/Quokka.h"

#include "quokka/Compatibility.h"
#include "quokka/Data.h"
#include "quokka/FileMetadata.h"
#include "quokka/Layout.h"
#include "quokka/Segment.h"
#include "quokka/Settings.h"
#include "quokka/Version.h"
#include "quokka/Writer.h"

namespace quokka {

int ExportBinary(const std::string& filename) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  Quokka quokka_protobuf;

  show_wait_box("quokka: start export");

  QLOG_INFO << absl::StrFormat("Exporter set in %s",
                               Settings::GetInstance().GetModeString());
  QLOGI << absl::StrFormat("Starting to export to %s", filename);

  Timer timer(absl::Now());

  // Always start by meta !
  WriteExporterMeta(&quokka_protobuf);
  ExportMeta(&quokka_protobuf);

  ExportSegments(&quokka_protobuf);
  ExportEnumAndStructures(&quokka_protobuf);

  replace_wait_box("quokka: exporting layout");
  ExportLayout(&quokka_protobuf);

  replace_wait_box("quokka: writing on the wire");
  std::string outfile = filename;

  std::fstream stream(outfile,
                      std::ios::binary | std::ios::out | std::ios::trunc);
  if (!quokka_protobuf.SerializeToOstream(&stream)) {
    QLOGE << "Unable to write the file, trying with a temp file.";
    outfile = "/tmp/Exported.quokka";
    stream = std::fstream(outfile,
                          std::ios::binary | std::ios::out | std::ios::trunc);
    if (!quokka_protobuf.SerializeToOstream(&stream)) {
      QLOG_FATAL << "Unable to write to temp file as well";
    }
  }

  QLOG_INFO << absl::StrFormat("File %s is written", outfile);
  QLOG_INFO << absl::StrFormat("quokka finished (took %.2fs)",
                               timer.ElapsedSeconds(absl::Now()));

  // Clean everything
  google::protobuf::ShutdownProtobufLibrary();

  hide_wait_box();

  return eOk;
}

ExporterMode GetModeFromArgument() {
  // Look for options on command line
  ExporterMode mode = ExporterMode::MODE_NORMAL;
  std::string quokka_mode = GetArgument("Mode", true);
  if (quokka_mode == "LIGHT") {
    mode = ExporterMode::MODE_LIGHT;
  } else if (quokka_mode == "FULL") {
    mode = ExporterMode::MODE_FULL;
  }

  return mode;
}

static error_t idaapi IdcQuokka(idc_value_t*, idc_value_t* res) {
  QLOG_DEBUG << "Calling Quokka from IDC";

  ExportBinary(GetOutputFileName());
  res->i64 = 0;

  return eOk;
}

static const char functionArgs[] = {0};
static const ext_idcfunc_t kquokkaIdcFunc = {"quokka", IdcQuokka, functionArgs,
                                             nullptr,  0,         EXTFUN_BASE};

std::string GetArgument(const char* name, bool to_upper) {
  const char* option = get_plugin_options(absl::StrCat("Quokka", name).c_str());

  if (option != nullptr) {
    std::string option_s(option);
    if (to_upper) {
      std::transform(
          option_s.begin(), option_s.end(), option_s.begin(),
          [](unsigned char c) -> unsigned char { return std::toupper(c); });
    }
    return option_s;
  }

  return "";
}

std::string GetOutputFileName() {
  std::string output_file = GetArgument("File");
  if (output_file.empty()) {
    char path[QMAXPATH] = {0};
    get_input_file_path(path, QMAXPATH);
    output_file = ReplaceFileExtension(path, ".quokka");
  }
  return output_file;
}

void UnsimplifyARM() {
  processor_t* processor = GetProcessor();
  if (processor->id == PLFM_ARM) {
    QLOGI << "Remove simplification in ARM assembly";
    int no = 0;
    processor->set_idp_options("ARM_SIMPLIFY", IDPOPT_BIT, &no, false);
    // TODO(dm) Find a way to access the initial value to restore it
  }
}

ssize_t idaapi UIHook(void* /* not used */, int event_id,
                      va_list /* arguments */) {
  if (event_id != ui_ready_to_run) {
    return 0;
  }

  const std::string auto_action = GetArgument("Auto");
  if (auto_action.empty()) {
    return 0;
  }

  QLOGI << "Auto Export";
  auto_wait();

  Settings::GetInstance().SetMode(GetModeFromArgument());
  ExportBinary(GetOutputFileName());

  // TODO(dm) Set the flag only when we are loading from a database
  // Or set an option to see if we need to save the database

  // set_database_flag(DBFL_KILL);
  qexit(0);
}

void SetLogLevel() {
  std::string cli_level = GetArgument("Log", true);
  LogLevel level = LogLevel::INFO;
  if (!cli_level.empty()) {
    if (cli_level == "DEBUG") {
      level = LogLevel::DEBUG;
    } else if (cli_level == "ERROR") {
      level = LogLevel::ERROR;
    }
  }
  Logger::GetInstance().SetLevel(level);
  Logger::GetInstance().SetDefaultUi(is_msg_inited());
}

bool PluginInit() {
  SetLogLevel();

  std::string version = GetVersion();
  QLOGI << absl::StrFormat("Starting to register Quokka (version %s)", version);

  addon_info_t addon_info;
  addon_info.cb = sizeof(addon_info_t);
  addon_info.id = "quokka";
  addon_info.name = "Quokka";
  addon_info.producer = "Quarkslab";
  addon_info.version = &*version.begin();
  addon_info.url = "https://www.quarkslab.com";
  addon_info.freeform = "";
  register_addon(&addon_info);

  // Unsimplify ARM
  UnsimplifyARM();

  if (!hook_to_notification_point(HT_UI, UIHook, nullptr)) {
    QLOGF << "Unable to register plugin";
    return false;
  }

  // Register the function to call from IDC
  if (!add_idc_func(kquokkaIdcFunc)) {
    QLOGE << "Cannot register IDC function";
    return false;
  }

  return true;
}

bool idaapi PluginRun(size_t) {
  QLOGI << "Quokka started";

  if (strlen(get_path(PATH_TYPE_IDB)) == 0) {
    error("You must open an IDB first\n");
  }

  std::vector<std::string> form = {
      "STARTITEM 0",
      "BUTTON YES Export",
      "BUTTON CANCEL Cancel",
      "HELP",
      "Export the current binary with quokka",
      absl::StrFormat("Version : %s", GetVersion()),
      "ENDHELP",
      "Quokka Plugin (@Quarkslab)",
      "\nExport the current binary ?\n",
      "<#Light mode#Choose a mode##LIGHT:R>",
      "<#Normal mode#NORMAL:R>",
      "<#Full mode#FULL:R>>",
  };

  std::string dialog = absl::StrJoin(form, "\n");
  ushort mode_input = 1;
  if (ask_form(dialog.c_str(), &mode_input) == ASKBTN_YES) {
    // Check if the mode has been selected
    ExporterMode mode;
    switch (mode_input) {
      case 0:
        mode = ExporterMode::MODE_LIGHT;
        break;
      case 1:
        mode = ExporterMode::MODE_NORMAL;
        break;
      case 2:
        mode = ExporterMode::MODE_FULL;
        break;
      default:
        assert(false && "Impossible choice for export mode");
    }

    Settings::GetInstance().SetMode(mode);

    std::string default_name = GetOutputFileName();
    const char* filename =
        ask_file(true, default_name.c_str(),
                 "FILTER Quokka Files|*.quokka\nSelect an output file");

    if (!filename || std::filesystem::exists(std::filesystem::path(filename)) &&
                         ask_yn(ASKBTN_NO, "'%s' already exists, overwrite?",
                                filename) != ASKBTN_YES) {
      return false;
    }

    return ExportBinary(std::string(filename)) == eOk;
  }

  return true;
}

void idaapi PluginTerminate() {
  unhook_from_notification_point(HT_UI, UIHook, nullptr);

  del_idc_func("Quokka");

  QLOGI << "Quokka: terminate";
}

}  // namespace quokka

#if IDA_SDK_VERSION > 740
static plugmod_t* idaapi init() { return new quokka::plugin_ctx_t; }
#else
int idaapi init(void) {
	quokka::PluginInit();
	return PLUGIN_KEEP;
}

void idaapi term(void)
{
  quokka::PluginTerminate();
}

bool idaapi run(size_t args) {
	return quokka::PluginRun(args);
};
#endif

plugin_t PLUGIN{
    IDP_INTERFACE_VERSION,
#if IDA_SDK_VERSION > 740
    PLUGIN_UNL | PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
#else
    PLUGIN_UNL,
    init,
    term,
    run,
#endif
    "This module exports binary",
    "Quokka help",
    "Quokka",
    "Alt+A",
};
