/**
 * @file tests/unit/test_plank_topology.cpp
 * @brief Tests for exact PLANK host-layout binding.
 */
#include "src/plank_topology.h"

#include <gtest/gtest.h>

namespace topology = plank::topology;

TEST(PlankTopology, PublishesVersionThirteenFeatureContract) {
  EXPECT_EQ(topology::protocol_version, 13U);
#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)
  EXPECT_EQ(topology::feature_flags, 0x247FFFFU);
  EXPECT_NE(topology::feature_flags & topology::feature_clipboard_sync, 0U);
#else
  EXPECT_EQ(topology::feature_flags, 0x207FFFFU);
  EXPECT_EQ(topology::feature_flags & topology::feature_clipboard_sync, 0U);
#endif
  EXPECT_NE(topology::feature_flags & topology::feature_nvfbc_hevc10_nvenc, 0U);
  EXPECT_NE(topology::feature_flags & topology::feature_fixed_transport_mtu, 0U);
  EXPECT_NE(topology::feature_flags & topology::feature_session_takeover, 0U);
  EXPECT_NE(topology::feature_flags & topology::feature_virtual_primary_connector, 0U);
  EXPECT_TRUE(topology::valid_virtual_mode("1024x2160"));
  EXPECT_TRUE(topology::valid_virtual_mode("2560x2160"));
  EXPECT_TRUE(topology::valid_virtual_mode("4096x2160"));
  EXPECT_TRUE(topology::valid_virtual_mode("5120x2160"));
  EXPECT_FALSE(topology::valid_virtual_mode("1280x720"));
  EXPECT_FALSE(topology::valid_virtual_mode("1280x1024"));
  EXPECT_TRUE(topology::valid_virtual_layout_modes(
    "dual-horizontal", "4096x2160", "1024x2160"
  ));
  EXPECT_TRUE(topology::valid_virtual_layout_modes(
    "dual-horizontal", "4096x2160", "1280x2160"
  ));
  EXPECT_TRUE(topology::valid_virtual_layout_modes(
    "dual-horizontal", "4096x2160", "4096x2160"
  ));
}

TEST(PlankTopology, BindsFirstVirtualConnectorOnlyWhenNegotiated) {
  using topology::feature_virtual_primary_connector;
  using topology::valid_virtual_primary_binding;
  using topology::virtual_primary_connector_matches;
  EXPECT_TRUE(valid_virtual_primary_binding("dual-horizontal", "single", -1, 0));
  EXPECT_FALSE(valid_virtual_primary_binding("dual-horizontal", "single", 1, 0));
  EXPECT_TRUE(valid_virtual_primary_binding("dual-horizontal", "single", 1,
                                            feature_virtual_primary_connector));
  EXPECT_FALSE(valid_virtual_primary_binding("dual-horizontal", "single", 2,
                                             feature_virtual_primary_connector));
  EXPECT_FALSE(valid_virtual_primary_binding("single", "single", 1,
                                             feature_virtual_primary_connector));
  EXPECT_FALSE(valid_virtual_primary_binding("dual-horizontal", "physical", 1,
                                             feature_virtual_primary_connector));
  EXPECT_TRUE(virtual_primary_connector_matches("single", 1, 2, "x11:DP-0"));
  EXPECT_FALSE(virtual_primary_connector_matches("single", 1, 2, "x11:DP-2"));
  EXPECT_TRUE(virtual_primary_connector_matches("physical", 1, 2, "x11:DP-2"));
  EXPECT_TRUE(virtual_primary_connector_matches("single", -1, 2, ""));
}

TEST(PlankTopology, AcceptsOnlyValidFixedQuicPayloadCeilings) {
  EXPECT_TRUE(topology::valid_quic_udp_payload_mtu(1200));
  EXPECT_TRUE(topology::valid_quic_udp_payload_mtu(1344));
  EXPECT_TRUE(topology::valid_quic_udp_payload_mtu(1452));
  EXPECT_TRUE(topology::valid_quic_udp_payload_mtu(65527));
  EXPECT_FALSE(topology::valid_quic_udp_payload_mtu(0));
  EXPECT_FALSE(topology::valid_quic_udp_payload_mtu(1199));
  EXPECT_FALSE(topology::valid_quic_udp_payload_mtu(65528));
}

TEST(PlankTopology, AcceptsOnlyExactEncodingTuples) {
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "software-cuda", "h264-10-444-software"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "nvenc-direct", "h264-8-444-nvenc"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "nvenc-direct", "hevc-8-444-nvenc"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "nvenc-direct", "hevc-10-444-nvenc"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "x11-native10", "software-cuda", "h264-10-444-software"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "x11-native10", "nvenc-direct", "hevc-10-444-nvenc"
  ));

  EXPECT_FALSE(topology::valid_encoding_tuple(
    "x11-native10", "nvenc-direct", "hevc-8-444-nvenc"
  ));
  EXPECT_FALSE(topology::valid_encoding_tuple(
    "x11-native10", "software-cuda", "h264-8-444-software"
  ));
  EXPECT_FALSE(topology::valid_encoding_tuple(
    "nvfbc", "software-cuda", "hevc-8-444-nvenc"
  ));
  EXPECT_FALSE(topology::valid_encoding_tuple(
    "nvfbc", "ffmpeg-nvenc", "h264-8-444-nvenc"
  ));
}

TEST(PlankTopology, AcceptsExactQualifiedLayouts) {
  EXPECT_EQ(topology::validate_layout_binding(
              "physical", "", "", "physical", "", "", 1),
            topology::layout_error::none);
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "4096x2160", "", "single", "4096x2160", "", 1),
            topology::layout_error::none);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "3840x2160", "1280x2160",
              "dual-horizontal", "3840x2160", "1280x2160", 2),
            topology::layout_error::none);
}

TEST(PlankTopology, EnforcesAdministratorDisplayPolicy) {
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("physical", "physical"));
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("single", "physical"));
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("dual-horizontal", "physical"));
  EXPECT_FALSE(topology::layout_allowed_by_startup_layout("physical", "single"));
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("single", "single"));
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("dual-horizontal", "single"));
  EXPECT_FALSE(topology::layout_allowed_by_startup_layout("dual-vertical", "physical"));
}

TEST(PlankTopology, RejectsMismatchBeforeLaunchState) {
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "1920x1080", "",
              "dual-horizontal", "1920x1080", "1024x2160", 2),
            topology::layout_error::mismatch);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "3840x2160", "1280x2160",
              "dual-horizontal", "3840x2160", "1024x2160", 2),
            topology::layout_error::mismatch);
}

TEST(PlankTopology, RejectsInvalidAndUnhealthyLayouts) {
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-vertical", "1920x1080", "",
              "dual-horizontal", "1920x1080", "1280x2160", 2),
            topology::layout_error::invalid_request);
  EXPECT_EQ(topology::validate_layout_binding(
              "physical", "1920x1080", "", "physical", "", "", 1),
            topology::layout_error::invalid_request);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "1920x1080", "1280x2160",
              "dual-horizontal", "1920x1080", "1280x2160", 1),
            topology::layout_error::unhealthy);
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "1920x1080", "1280x2160",
              "single", "1920x1080", "", 1),
            topology::layout_error::invalid_request);
}
