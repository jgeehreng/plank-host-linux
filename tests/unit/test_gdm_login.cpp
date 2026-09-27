/**
 * @file tests/unit/test_gdm_login.cpp
 * @brief Policy tests for GDM post-PAM session start.
 */
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <unistd.h>

#include "src/session/gdm_login.h"

namespace session = plank::session;

TEST(GdmLogin, AcceptsBoundedPamUsernames) {
  EXPECT_TRUE(session::valid_gdm_username("artist"));
  EXPECT_TRUE(session::valid_gdm_username("user.name"));
  EXPECT_FALSE(session::valid_gdm_username(""));
  EXPECT_FALSE(session::valid_gdm_username("user\nname"));
  EXPECT_FALSE(session::valid_gdm_username("user\rname"));
  EXPECT_FALSE(session::valid_gdm_username(std::string {'u', '\0', 'x'}));
  EXPECT_FALSE(session::valid_gdm_username(std::string(257, 'a')));
}

TEST(GdmLogin, RejectsEmptySecretsWithoutTalkingToGdm) {
  std::vector<std::string> secrets;
  EXPECT_FALSE(session::complete_gdm_login("artist", secrets));
  secrets.emplace_back("");
  EXPECT_FALSE(session::complete_gdm_login("artist", secrets));
}

TEST(GdmLogin, FailsClosedWithoutRoot) {
  if (geteuid() == 0) {
    GTEST_SKIP() << "complete_gdm_login talks to the GDM helper when running as root";
  }
  std::vector<std::string> secrets {"x"};
  EXPECT_FALSE(session::complete_gdm_login("artist", secrets));
}
