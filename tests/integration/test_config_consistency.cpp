/**
 * @file tests/integration/test_config_consistency.cpp
 * @brief PLANK configuration parser and documentation consistency tests.
 */

#include "../tests_common.h"

#include <algorithm>
#include <iterator>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "src/config.h"
#include "src/file_handler.h"

namespace {
  std::set<std::string, std::less<>> extract_runtime_options() {
    const std::string content = file_handler::read_file("src/config.cpp");
    const std::vector patterns = {
      std::regex(R"DELIM((?:string_f|path_f|string_restricted_f)\s*\(\s*vars\s*,\s*"([^"]+)")DELIM"),
      std::regex(R"DELIM((?:int_f|int_between_f)\s*\(\s*vars\s*,\s*"([^"]+)")DELIM"),
      std::regex(R"DELIM(bool_f\s*\(\s*vars\s*,\s*"([^"]+)")DELIM"),
      std::regex(R"DELIM((?:double_f|double_between_f)\s*\(\s*vars\s*,\s*"([^"]+)")DELIM"),
      std::regex(R"DELIM(generic_f\s*\(\s*vars\s*,\s*"([^"]+)")DELIM"),
      std::regex(R"DELIM(map_int_int_f\s*\(\s*vars\s*,\s*"([^"]+)")DELIM"),
    };

    std::set<std::string, std::less<>> options;
    for (const auto &pattern : patterns) {
      for (std::sregex_iterator iterator(content.begin(), content.end(), pattern), end;
           iterator != end;
           ++iterator) {
        options.insert((*iterator)[1].str());
      }
    }
    return options;
  }

  std::set<std::string, std::less<>> extract_documented_options() {
    const std::string content = file_handler::read_file("docs/configuration.md");
    const std::regex heading(R"(^###\s+([^#\r\n]+?)\s*$)");
    std::set<std::string, std::less<>> options;
    std::istringstream lines(content);
    for (std::string line; std::getline(lines, line);) {
      std::smatch match;
      if (std::regex_match(line, match, heading)) {
        options.insert(match[1].str());
      }
    }
    return options;
  }

  std::string join(const std::set<std::string, std::less<>> &values) {
    std::string result;
    for (const auto &value : values) {
      result += result.empty() ? value : ", " + value;
    }
    return result;
  }
}  // namespace

TEST(ConfigParserTest, AcceptsIniSectionsAndGlobalKeys) {
  const auto values = config::parse_config(R"(
# PLANK host profile
[network]
mdns_discovery = false

[x264-encoder]
sw_vbv_maxrate_percentage = 150
sw_vbv_buffer_frames = 4
)");

  ASSERT_EQ(values.size(), 3);
  EXPECT_EQ(values.at("mdns_discovery"), "false");
  EXPECT_EQ(values.at("sw_vbv_maxrate_percentage"), "150");
  EXPECT_EQ(values.at("sw_vbv_buffer_frames"), "4");
  EXPECT_FALSE(values.contains("network"));
  EXPECT_FALSE(values.contains("x264-encoder"));
}

TEST(ConfigParserTest, IgnoresCommentsAndEmptySections) {
  const auto values = config::parse_config(R"(
# comment
[security] # comment
[]
[ ]
cert = /etc/plank/tls/cert.pem
)");

  ASSERT_EQ(values.size(), 1);
  EXPECT_EQ(values.at("cert"), "/etc/plank/tls/cert.pem");
}

TEST(ConfigConsistencyTest, RuntimeAndDocumentedOptionsMatch) {
  const auto runtime = extract_runtime_options();
  const auto documented = extract_documented_options();

  std::set<std::string, std::less<>> missing;
  std::set_difference(runtime.begin(), runtime.end(),
                      documented.begin(), documented.end(),
                      std::inserter(missing, missing.end()));
  std::set<std::string, std::less<>> obsolete;
  std::set_difference(documented.begin(), documented.end(),
                      runtime.begin(), runtime.end(),
                      std::inserter(obsolete, obsolete.end()));

  EXPECT_TRUE(missing.empty()) << "Undocumented runtime options: " << join(missing);
  EXPECT_TRUE(obsolete.empty()) << "Documented but unsupported options: " << join(obsolete);
}

TEST(ConfigConsistencyTest, RuntimeOptionsMatchPlankProductPolicy) {
  const std::set<std::string, std::less<>> expected {
    "adapter_name",
    "allow_root_login",
    "audio_sink",
    "cert",
    "file_state",
    "key_repeat_delay",
    "key_repeat_frequency",
    "keybindings",
    "log_path",
    "min_log_level",
    "min_threads",
    "minimum_fps_target",
    "nvenc_h264_cavlc",
    "nvenc_preset",
    "nvenc_spatial_aq",
    "nvenc_split_encode",
    "nvenc_twopass",
    "nvenc_vbv_increase",
    "ping_timeout",
    "pkey",
    "port",
    "publish_session_user",
    "startup_layout",
    "mdns_discovery",
    "host_name",
    "sw_preset",
    "sw_scenecut",
    "sw_tune",
    "sw_vbv_buffer_frames",
    "sw_vbv_maxrate_percentage",
  };

  const auto runtime = extract_runtime_options();
  EXPECT_EQ(runtime, expected)
    << "PLANK runtime configuration drifted. Actual: " << join(runtime);
}

TEST(ConfigConsistencyTest, OmitsGlobalVideoBackendSelectors) {
  const auto runtime = extract_runtime_options();
  const auto documented = extract_documented_options();

  EXPECT_FALSE(runtime.contains("capture"));
  EXPECT_FALSE(runtime.contains("encoder"));
  EXPECT_FALSE(documented.contains("capture"));
  EXPECT_FALSE(documented.contains("encoder"));
}
