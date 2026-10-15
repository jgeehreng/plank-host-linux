/**
 * @file tests/unit/test_admission_networks.cpp
 * @brief Office networks that may sign in without a broker admission.
 */
#include <gtest/gtest.h>

#include "src/auth/admission_networks.h"

namespace admission = plank::admission;

TEST(AdmissionNetworks, EmptyExemptsNothing) {
  EXPECT_FALSE(admission::exempt("", "192.168.76.10"));
  EXPECT_FALSE(admission::exempt("  ,  ", "192.168.76.10"));
}

TEST(AdmissionNetworks, MatchesIPv4Prefixes) {
  const std::string office = "192.168.76.0/24, 10.20.0.0/16";
  EXPECT_TRUE(admission::exempt(office, "192.168.76.10"));
  EXPECT_TRUE(admission::exempt(office, "192.168.76.255"));
  EXPECT_FALSE(admission::exempt(office, "192.168.77.10"));
  EXPECT_TRUE(admission::exempt(office, "10.20.255.1"));
  EXPECT_FALSE(admission::exempt(office, "10.21.0.1"));
  EXPECT_FALSE(admission::exempt(office, "8.8.8.8"));
}

TEST(AdmissionNetworks, PrefixesThatAreNotByteAligned) {
  EXPECT_TRUE(admission::exempt("172.16.0.0/12", "172.31.200.1"));
  EXPECT_FALSE(admission::exempt("172.16.0.0/12", "172.32.0.1"));
  EXPECT_TRUE(admission::exempt("192.168.76.128/25", "192.168.76.200"));
  EXPECT_FALSE(admission::exempt("192.168.76.128/25", "192.168.76.100"));
}

TEST(AdmissionNetworks, BareAddressIsOneHost) {
  EXPECT_TRUE(admission::exempt("192.168.76.43", "192.168.76.43"));
  EXPECT_FALSE(admission::exempt("192.168.76.43", "192.168.76.44"));
}

TEST(AdmissionNetworks, IPv6AndMappedIPv4) {
  EXPECT_TRUE(admission::exempt("fd00:76::/32", "fd00:76:1::5"));
  EXPECT_FALSE(admission::exempt("fd00:76::/32", "fd00:77::5"));
  EXPECT_TRUE(admission::exempt("192.168.76.0/24", "::ffff:192.168.76.9"));
  EXPECT_FALSE(admission::exempt("192.168.76.0/24", "fd00:76::1"));
}

TEST(AdmissionNetworks, AnyMalformedEntryExemptsNothing) {
  for (const char *bad : {"192.168.76.0/33", "192.168.76/24", "office", "192.168.76.0/2x",
                          "192.168.76.0/24, nonsense", "fd00::/129", "192.168.76.0/"}) {
    EXPECT_FALSE(admission::parse_networks(bad)) << bad;
    EXPECT_FALSE(admission::exempt(bad, "192.168.76.10")) << bad;
  }
  EXPECT_FALSE(admission::exempt("192.168.76.0/24", "not-an-address"));
}
