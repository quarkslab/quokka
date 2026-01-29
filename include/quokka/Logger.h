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
 * @file Logger.h
 * Logger management
 */

#ifndef QUOKKA_LOGGER_H
#define QUOKKA_LOGGER_H

#include <ctime>
#include <utility>

// clang-format off: Compatibility.h must come before ida headers
#include "Compatibility.h"
// clang-format on
#include <pro.h>
#include <kernwin.hpp>

#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"

#include "Windows.h"

namespace quokka {

/**
 * Log level
 */
enum LogLevel : short { DEBUG = 0, WARNING, INFO, ERROR, FATAL };

/**
 * ---------------------------------------------
 * quokka::Record
 * ---------------------------------------------
 * A record represents a log message
 */
class Record {
 private:
  LogLevel m_level;          ///< Current log level
  const size_t m_line;       ///< Line of the log
  const char* const m_func;  ///< Function from the log
  std::string m_message;     ///< Log message

 public:
  /**
   * Constructor
   * @param level Log level
   * @param func Function where the record was created
   * @param line Line pointed
   */
  Record(LogLevel level, const char* func, size_t line)
      : m_level(level), m_line(line), m_func(func) {};

  /**
   * Return an pointer of self
   * @return
   */
  Record& ref() { return *this; }

  /**
   * Append the message to the current record
   * @param data Message to add
   * @return A reference of self
   */
  Record& operator<<(const std::string& data) {
    m_message.append(data);
    return *this;
  }

  /**
   * Get the current log level
   * @return Log level
   */
  [[nodiscard]] LogLevel GetLevel() const { return this->m_level; }

  /**
   * Get the log message
   * @return Record message
   */
  [[nodiscard]] std::string GetMessage() const { return this->m_message; }

  /**
   * Get the full version of the message
   * @return A complete message
   */
  [[nodiscard]] std::string GetFullMessage() const {
    return absl::StrCat(m_func, " ", m_line, ":\t", this->m_message);
  }
};

class Logger {
 private:
  /**
   * Private constructor for singleton pattern
   */
  explicit Logger() {
    if (!absl::LoadTimeZone("France/Paris", &m_tz)) {
      m_tz = absl::UTCTimeZone();
    }
  };

  LogLevel m_level = FATAL;  ///< Default log level
  absl::TimeZone m_tz;       ///< Default time zone

  /**
   * Is the logger is able to access IDA console ?
   */
  bool m_defaultui = false;

 public:
  /**
   * Convert the log level to a string
   * @param level Log level
   * @return Value
   */
  static const char* LogLevelToString(LogLevel level) {
    switch (level) {
      case DEBUG:
        return "DEBUG";
      case WARNING:
        return "WARNING";
      case INFO:
        return "INFO";
      case ERROR:
        return "ERROR";
      case FATAL:
        return "FATAL";
    }

    return "UNKNOWN";
  }

  void SetDefaultUi(bool value) { m_defaultui = value; }

  /**
   * Check if the current level is enough to emit the record
   * @param level Level to check
   * @return Bool for success
   */
  bool CheckLevel(LogLevel level) { return level >= m_level; }

  /**
   * Setter for level
   * @param level Level to set
   */
  void SetLevel(LogLevel level) { this->m_level = level; }

  /**
   * Emit a record on STDERR
   *
   * If the IDA console is accessible, it will also emit it to it.
   *
   * @param record Record to be emitted
   */
  void WriteLine(const Record& record) {
    std::string message = (m_level == LogLevel::DEBUG) ? record.GetFullMessage()
                                                       : record.GetMessage();

    std::string formatted =
        absl::StrCat(LogLevelToString(record.GetLevel()), " ",
                     absl::FormatTime("%H:%M:%S", absl::Now(), this->m_tz), " ",
                     message, "\n");

    fputs(formatted.c_str(), stderr);
    fflush(stderr);

    if (m_defaultui) {
      // TODO(dm) fix me because this is not available when running tests
      msg("%s", formatted.c_str());
    }
  }

  /**
   * Singleton pattern
   * @return An instance to self
   */
  static Logger& GetInstance() {
    static Logger instance;
    return instance;
  }

  /**
   * Add a record
   * @param record Record to emit
   */
  void operator+=(const Record& record) {
    if (CheckLevel(record.GetLevel())) {
      WriteLine(record);
    }
  }
};

#define QLOG(level) \
  Logger::GetInstance() += Record(level, __PRETTY_FUNCTION__, __LINE__).ref()
#define QLOG_DEBUG QLOG(LogLevel::DEBUG)
#define QLOG_INFO QLOG(LogLevel::INFO)
#define QLOG_WARNING QLOG(LogLevel::WARNING)
#define QLOG_ERROR QLOG(LogLevel::ERROR)
#define QLOG_FATAL QLOG(LogLevel::FATAL)

#define QLOGD QLOG_DEBUG
#define QLOGI QLOG_INFO
#define QLOGW QLOG_WARNING
#define QLOGE QLOG_ERROR
#define QLOGF QLOG_FATAL

}  // namespace quokka

#endif  // QUOKKA_LOGGER_H
