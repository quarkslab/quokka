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
 * @file Settings.h
 * Settings for quokka
 */

#ifndef QUOKKA_SETTINGS_H
#define QUOKKA_SETTINGS_H

#include "Version.h"
#include "Windows.h"

namespace quokka {

/**
 * Exporter mode
 *
 * The light mode will not export instructions
 * @warning Light mode not implemented
 */
enum ExporterMode : short {
  MODE_LIGHT = 0,
  MODE_NORMAL,
  MODE_FULL,
};

/**
 * ---------------------------------------------
 * quokka::Settings
 * ---------------------------------------------
 * Settings singleton
 */
class Settings {
 private:
  /**
   * Private constructor
   */
  explicit Settings() = default;

  /**
   * Exporter mode. Defaults to NORMAL.
   */
  ExporterMode mode = MODE_NORMAL;

 public:
  /**
   * Singleton pattern
   * @return `quokka::Settings`
   */
  static Settings& GetInstance() {
    static Settings instance;
    return instance;
  }

  /**
   * Accessor for the exporter mode
   * @return ExporterMode
   */
  [[nodiscard]] ExporterMode GetMode() const { return mode; }

  /**
   * Setter for the exporter mode
   * @param mode_ Mode to set
   */
  void SetMode(ExporterMode mode_) { this->mode = mode_; }

  /**
   * Should we export instructions ?
   * @return Boolean
   */
  [[nodiscard]] bool ExportInstructions() const {
    return this->mode >= MODE_NORMAL;
  }

  /**
   * Should we export the instruction strings?
   * @return Boolean
   */
  [[nodiscard]] bool ExportInstructionStrings() const {
    return this->mode >= MODE_FULL;
  }

  /**
   * GetString Value
   * @return The string representation of the mode
   */
  [[nodiscard]] std::string GetModeString() const {
    switch (this->mode) {
      case ExporterMode::MODE_LIGHT:
        return "LIGHT";
      case ExporterMode::MODE_NORMAL:
        return "NORMAL";
      case ExporterMode::MODE_FULL:
        return "FULL";
    }

    assert(false && "Should not reach the end of the function");
  }
};

}  // namespace quokka

#endif  // QUOKKA_SETTINGS_H
