//
// Created by alexis on 11/05/2020.
//

#include <google/protobuf/util/message_differencer.h>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"

#include "gtest/gtest.h"

#include "ProtoWrapper.h"

// Generated / Expected
class DISABLED_ProtoTest
    : public ::testing::TestWithParam<std::tuple<std::string, std::string>> {
 protected:
  static quokka::Quokka* generated;
  static quokka::Quokka* expected;

 public:
  void SetUp() override {
    generated = new quokka::Quokka();
    expected = new quokka::Quokka();

    GOOGLE_PROTOBUF_VERIFY_VERSION;
    const auto filenames = GetParam();

    std::fstream input(std::get<0>(filenames), std::ios::in | std::ios::binary);
    if (!generated->ParseFromIstream(&input)) {
      FAIL() << absl::StrCat("Unable to load generated file ",
                             std::get<0>(filenames));
    }

    std::fstream input_2(std::get<1>(filenames),
                         std::ios::in | std::ios::binary);
    if (!expected->ParseFromIstream(&input_2)) {
      FAIL() << absl::StrCat("Unable to load expected file ",
                             std::get<1>(filenames));
    }
  }

  // static void TearDownTestSuite() {
  void TearDown() override {
    delete generated;
    generated = nullptr;

    delete expected;
    expected = nullptr;
  }

  // void TearDown() override {}
};

quokka::Quokka* DISABLED_ProtoTest::generated = nullptr;
quokka::Quokka* DISABLED_ProtoTest::expected = nullptr;

namespace gutils = google::protobuf::util;

// From :
// https://github.com/protocolbuffers/protobuf/blob/master/src/google/protobuf/util/message_differencer_unittest.cc#L68
const google::protobuf::FieldDescriptor* GetFieldDescriptor(
    const google::protobuf::Message& message, const std::string& field_name) {
  std::vector<std::string> field_path = absl::StrSplit(field_name, '.');

  const google::protobuf::Descriptor* descriptor = message.GetDescriptor();
  const google::protobuf::FieldDescriptor* field = nullptr;
  for (auto& i : field_path) {
    field = descriptor->FindFieldByName(i);
    descriptor = field->message_type();
  }
  return field;
}

TEST_P(DISABLED_ProtoTest, ProtobufEquality) {
  gutils::MessageDifferencer differencer;

  std::vector<std::string> ignored_fields = {
      "exporter_meta.version",
      "meta.ida_version",

      "instructions.mnemonic_index",
      "instructions.operand_index",
      "function_chunks.blocks.instructions_index",

      "functions.function_chunks_index",
      "functions.chunk_edges.source",
      "functions.chunk_edges.destination",
      "functions.block_positions.block_id",

      "data.name_index",
      "data.value_index",

      "comments.string_idx",
      "comments.location",

      "references.source",
      "references.destination",
  };

  for (const auto& field : ignored_fields) {
    differencer.IgnoreField(GetFieldDescriptor(*generated, field));
  }
  differencer.set_repeated_field_comparison(gutils::MessageDifferencer::AS_SET);
  differencer.set_report_ignores(false);
  differencer.set_report_moves(false);

  /*std::string output;
  differencer.ReportDifferencesToString(&output);*/

  EXPECT_TRUE(differencer.Compare(*generated, *expected));
}

std::vector<std::tuple<std::string, std::string>> config;

INSTANTIATE_TEST_SUITE_P(
    DISABLED_ProtobufValues, DISABLED_ProtoTest, testing::ValuesIn(config),
    [](const testing::TestParamInfo<std::tuple<std::string, std::string>>&
           info) {
      std::string name =
          std::filesystem::path(std::get<0>(info.param)).filename().string();
      std::replace_if(
          name.begin(), name.end(), [](char c) { return !std::isalnum(c); },
          '_');
      return name;
    });

int main(int argc, char** argv) {
  std::string extension(".Quokka");
  std::filesystem::path sample_dir("samples");
  std::filesystem::path expected_dir("expected");

  for (const auto& generated :
       std::filesystem::directory_iterator(expected_dir)) {
    if (generated.path().extension() == extension) {
      std::filesystem::path sample_file = sample_dir;
      sample_file /= generated.path().filename();

      if (std::filesystem::exists(sample_file)) {
        config.emplace_back(generated.path().string(), sample_file);
      }
    }
  }

  for (const auto& t : config) {
    std::cout << std::get<0>(t) << "-" << std::get<1>(t) << std::endl;
  }
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}