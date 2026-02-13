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
 * @file LzmaStreambuf.h
 * A std::streambuf that LZMA-compresses data on-the-fly.
 */

#ifndef QUOKKA_LZMA_STREAMBUF_H
#define QUOKKA_LZMA_STREAMBUF_H

#include <cstdint>
#include <ostream>
#include <streambuf>

#include <lzma.h>

namespace quokka {

/**
 * A std::streambuf that LZMA-compresses data on-the-fly and writes the
 * compressed output directly to a destination std::ostream.
 *
 * Usage:
 *   std::ofstream file("out.bin", std::ios::binary);
 *   LzmaStreambuf lzma_buf(file);
 *   std::ostream lzma_out(&lzma_buf);
 *   protobuf.SerializeToOstream(&lzma_out);
 *   lzma_buf.finish();  // flush & finalize the LZMA stream
 */
class LzmaStreambuf : public std::streambuf {
 public:
  explicit LzmaStreambuf(std::ostream& dest,
                         uint32_t preset = LZMA_PRESET_DEFAULT)
      : dest_(dest), lzma_stream_(LZMA_STREAM_INIT), finished_(false) {
    lzma_ret ret = lzma_easy_encoder(&lzma_stream_, preset, LZMA_CHECK_CRC64);
    if (ret != LZMA_OK) {
      ok_ = false;
      return;
    }
    ok_ = true;
    setp(in_buf_, in_buf_ + kBufSize);
  }

  ~LzmaStreambuf() override {
    if (!finished_) finish();
    lzma_end(&lzma_stream_);
  }

  // Non-copyable, non-movable
  LzmaStreambuf(const LzmaStreambuf&) = delete;
  LzmaStreambuf& operator=(const LzmaStreambuf&) = delete;

  /// Finalize the LZMA stream (must be called before reading sizes).
  bool finish() {
    if (finished_) return ok_;
    finished_ = true;
    // Flush whatever remains in the put-area, then signal LZMA_FINISH.
    ok_ = flush_to_lzma(LZMA_FINISH) && ok_;
    return ok_;
  }

  bool ok() const { return ok_; }
  uint64_t total_in() const { return lzma_stream_.total_in; }
  uint64_t total_out() const { return lzma_stream_.total_out; }

 protected:
  int overflow(int ch) override {
    if (!ok_) return EOF;
    // Flush the full buffer first
    if (!flush_to_lzma(LZMA_RUN)) {
      ok_ = false;
      return EOF;
    }
    // Now the buffer is reset, safe to write the new character
    if (ch != EOF) {
      *pptr() = static_cast<char>(ch);
      pbump(1);
    }
    return (ch == EOF) ? 0 : ch;
  }

  int sync() override {
    if (!ok_) return -1;
    if (!flush_to_lzma(LZMA_RUN)) {
      ok_ = false;
      return -1;
    }
    return 0;
  }

 private:
    static constexpr size_t kBufSize = 65535;

  bool flush_to_lzma(lzma_action action) {
    lzma_stream_.next_in = reinterpret_cast<const uint8_t*>(pbase());
    lzma_stream_.avail_in = static_cast<size_t>(pptr() - pbase());

    do {
      lzma_stream_.next_out = out_buf_;
      lzma_stream_.avail_out = kBufSize;

      lzma_ret ret = lzma_code(&lzma_stream_, action);
      if (ret != LZMA_OK && ret != LZMA_STREAM_END) return false;

      size_t have = kBufSize - lzma_stream_.avail_out;
      if (have > 0) {
        dest_.write(reinterpret_cast<const char*>(out_buf_), have);
        if (!dest_) return false;
      }

      if (ret == LZMA_STREAM_END) break;
    } while (lzma_stream_.avail_in > 0 || lzma_stream_.avail_out == 0);

    setp(in_buf_, in_buf_ + kBufSize);
    return true;
  }

  std::ostream& dest_;
  lzma_stream lzma_stream_;
  char in_buf_[kBufSize];
  uint8_t out_buf_[kBufSize];
  bool ok_;
  bool finished_;
};

}  // namespace quokka

#endif  // QUOKKA_LZMA_STREAMBUF_H
