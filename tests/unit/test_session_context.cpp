/**
 * @file tests/unit/test_session_context.cpp
 * @brief Security policy tests for PLANK logind session selection.
 */
#include <gtest/gtest.h>

#include "src/session/session_context.h"

namespace session = plank::session;

namespace {
  session::descriptor_t valid_session() {
    return {
      "c7",
      1000,
      "seat0",
      "x11",
      "user",
      "active",
      true,
      false,
    };
  }

  session::update_t valid_update() {
    return {
      7,
      valid_session(),
      {":0", "/run/user/1000/gdm/Xauthority", "/run/user/1000",
       "unix:path=/run/user/1000/bus", "unix:/run/user/1000/pulse/native",
       "/home/test/.config/pulse/cookie"},
    };
  }
}  // namespace

TEST(SessionContext, AcceptsActiveLocalSeat0UserAndGreeter) {
  auto descriptor = valid_session();
  EXPECT_TRUE(session::eligible_graphical_session(descriptor));

  descriptor.session_class = "greeter";
  EXPECT_TRUE(session::eligible_graphical_session(descriptor));
}

TEST(SessionContext, RejectsInactiveRemoteOrNonSeat0Sessions) {
  auto descriptor = valid_session();
  descriptor.active = false;
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.remote = true;
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.seat = "seat1";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.state = "closing";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));
}

TEST(SessionContext, RejectsUnsupportedSessionTypesAndClasses) {
  auto descriptor = valid_session();
  descriptor.type = "tty";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.type = "wayland";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.session_class = "lock-screen";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));
}

TEST(SessionContext, RoundTripsBoundedDesktopUpdates) {
  const auto update = valid_update();
  const auto message = session::session_update_message(update);
  const auto parsed = session::parse_session_update(message);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->generation, update.generation);
  EXPECT_EQ(parsed->session.id, update.session.id);
  EXPECT_EQ(parsed->session.uid, update.session.uid);
  EXPECT_EQ(parsed->environment.display, update.environment.display);
  EXPECT_EQ(parsed->environment.pulse_cookie, update.environment.pulse_cookie);
}

TEST(SessionContext, RejectsMalformedOrIneligibleDesktopUpdates) {
  auto update = valid_update();
  auto message = session::session_update_message(update);
  ASSERT_FALSE(message.empty());
  message.pop_back();
  EXPECT_FALSE(session::parse_session_update(message));

  update.session.remote = true;
  EXPECT_TRUE(session::session_update_message(update).empty());

  update = valid_update();
  update.generation = 0;
  EXPECT_TRUE(session::session_update_message(update).empty());
}

TEST(SessionContext, RoundTripsBoundedDisplayRequests) {
  const session::display_request_t single {
    session::display_request_t::action_t::acquire,
    "single", "2560x1600", {}, 1000
  };
  const auto singleMessage = session::display_request_message(single);
  const auto parsedSingle = session::parse_display_request(singleMessage);
  ASSERT_TRUE(parsedSingle);
  EXPECT_EQ(parsedSingle->layout, single.layout);
  EXPECT_EQ(parsedSingle->mode_1, single.mode_1);
  EXPECT_TRUE(parsedSingle->mode_2.empty());
  EXPECT_EQ(parsedSingle->account_uid, single.account_uid);

  const session::display_request_t dual {
    session::display_request_t::action_t::acquire,
    "dual-horizontal", "4096x2160", "1024x2160", 1000
  };
  const auto parsedDual = session::parse_display_request(
    session::display_request_message(dual)
  );
  ASSERT_TRUE(parsedDual);
  EXPECT_EQ(parsedDual->mode_2, dual.mode_2);

  for (const auto action : {
         session::display_request_t::action_t::activate,
         session::display_request_t::action_t::release,
       }) {
    const session::display_request_t control {action, {}, {}, {}, 1000};
    const auto parsed = session::parse_display_request(
      session::display_request_message(control)
    );
    ASSERT_TRUE(parsed);
    EXPECT_EQ(parsed->action, action);
    EXPECT_EQ(parsed->account_uid, 1000U);
  }
}

TEST(SessionContext, RejectsMalformedDisplayRequests) {
  EXPECT_TRUE(session::display_request_message(
    {session::display_request_t::action_t::acquire,
     "single", "1280x720", {}, 1000}
  ).empty());
  EXPECT_TRUE(session::display_request_message(
    {session::display_request_t::action_t::acquire,
     "single", "2560x1600", "1024x2160", 1000}
  ).empty());
  EXPECT_TRUE(session::display_request_message(
    {session::display_request_t::action_t::acquire,
     "dual-horizontal", "4096x2160", {}, 1000}
  ).empty());
  EXPECT_FALSE(session::display_request_message(
    {session::display_request_t::action_t::acquire,
     "dual-horizontal", "4096x2160", "1280x2160", 1000}
  ).empty());
  EXPECT_TRUE(session::display_request_message(
    {session::display_request_t::action_t::acquire,
     "single", "2560x1600", {}, 0}
  ).empty());
  auto truncated = session::display_request_message(
    {session::display_request_t::action_t::acquire,
     "single", "2560x1600", {}, 1000}
  );
  ASSERT_FALSE(truncated.empty());
  truncated.pop_back();
  EXPECT_FALSE(session::parse_display_request(truncated));
}

TEST(SessionContext, RoundTripsTemporaryRuntimeDisplayState) {
  const session::runtime_display_state_t state {
    "dual-horizontal", "3840x2160", "1280x2160", 1000
  };
  const auto message = session::runtime_display_state_message(state);
  const auto parsed = session::parse_runtime_display_state(message);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->layout, state.layout);
  EXPECT_EQ(parsed->mode_1, state.mode_1);
  EXPECT_EQ(parsed->mode_2, state.mode_2);
  EXPECT_EQ(parsed->lease_uid, state.lease_uid);

  auto truncated = message;
  truncated.pop_back();
  EXPECT_FALSE(session::parse_runtime_display_state(truncated));
  EXPECT_TRUE(session::runtime_display_state_message(
    {"single", "1280x1024", {}, 1000}
  ).empty());
}

TEST(SessionContext, ReadsSecondaryVisibilityFromOwnedOverlay) {
  constexpr std::string_view prefix =
    "# Generated by PLANK; do not edit.\n"
    "Section \"Device\"\n";
  EXPECT_EQ(session::secondary_output_visible_from_overlay(
              std::string {prefix} +
              "  Option \"MetaModes\" \"DFP-0: 2560x2160 +0+0, DFP-2: NULL\"\n"),
            false);
  EXPECT_EQ(session::secondary_output_visible_from_overlay(
              std::string {prefix} +
              "  Option \"MetaModes\" \"DFP-0: 4096x2160 +0+0, DFP-2: 1024x2160 +4096+0\"\n"),
            true);
  EXPECT_FALSE(session::secondary_output_visible_from_overlay(
                 "# foreign configuration\nOption \"MetaModes\" \"DFP-2: NULL\"\n")
                 .has_value());
}
