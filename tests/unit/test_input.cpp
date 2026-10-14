/**
 * @file tests/unit/test_input.cpp
 * @brief Tests for retained stream input and raw-HID tablet lifecycle behavior.
 */

// standard includes
#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>

extern "C" {
#include <moonlight-common-c/src/plank.h>
#ifdef PLANK_TRANSPORT
  #include <plank_transport_input.h>
#endif
}

// local includes
#include "src/config.h"
#include "src/globals.h"
#include "src/input.h"
#include "src/platform/virtualhid_input.h"
#include "src/process.h"
#include "src/raw_hid_tablet.h"
#include "src/utility.h"

#include <gtest/gtest.h>

namespace {
  std::vector<std::uint8_t> make_raw_hid_frame(
    const PLANK_RAW_HID_MESSAGE_TYPE type,
    const std::uint16_t interface_id,
    const std::uint16_t generation,
    const void *payload,
    const std::size_t payload_size
  ) {
    std::vector<std::uint8_t> frame(sizeof(PLANK_RAW_HID_WIRE_HEADER) + payload_size);
    PLANK_RAW_HID_WIRE_HEADER header {};
    header.magic = util::endian::little(static_cast<std::uint32_t>(PLANK_RAW_HID_WIRE_MAGIC));
    header.version = util::endian::little(static_cast<std::uint16_t>(PLANK_RAW_HID_WIRE_VERSION));
    header.type = util::endian::little(static_cast<std::uint16_t>(type));
    header.interfaceId = util::endian::little(interface_id);
    header.generation = util::endian::little(generation);
    header.payloadLength = util::endian::little(static_cast<std::uint32_t>(payload_size));
    std::memcpy(frame.data(), &header, sizeof(header));
    if (payload_size != 0) {
      std::memcpy(frame.data() + sizeof(header), payload, payload_size);
    }
    return frame;
  }

  std::vector<std::uint8_t> make_raw_hid_device_frame(
    const std::uint16_t generation,
    const std::uint32_t product = 0x0357
  ) {
    PLANK_RAW_HID_DEVICE_MESSAGE device {};
    device.interfaceCount = util::endian::little<std::uint16_t>(1);
    device.bus = util::endian::little<std::uint16_t>(3);
    device.vendor = util::endian::little<std::uint32_t>(0x056a);
    device.product = util::endian::little(product);
    std::memcpy(device.name, "Any exact raw tablet", 20);
    std::memcpy(device.unique, "model-independent", 17);
    return make_raw_hid_frame(PLANK_RAW_HID_DEVICE, 0, generation, &device, sizeof(device));
  }

  /**
   * @brief Fixture that installs a fake global virtual input backend.
   */
  class InputRetainedSessionTest: public ::testing::Test {
  protected:
    /**
     * @brief Install an observable fake virtual-input runtime.
     */
    void SetUp() override {
      ASSERT_FALSE(task_pool.running());
      auto platform_input = platf::input();
      ASSERT_TRUE(platform_input);
      auto &context = platf::virtualhid::get_input_context(platform_input);
      context = platf::virtualhid::input_context_t {lvh::BackendKind::fake};
      ASSERT_NE(context.runtime, nullptr);
      ASSERT_NE(context.mouse, nullptr);
      mouse = context.mouse.get();
      input::testing::set_platform_input(std::move(platform_input));
    }

    /**
     * @brief Release input and discard callbacks before destroying the fake backend.
     */
    void TearDown() override {
      for (auto &[session, connection_id] : sessions) {
        input::reset(session, connection_id);
      }
      // alloc() also queues a mouse nudge. Never let any callback from this
      // fixture run against the next test's replacement platform backend.
      static_cast<task_pool_util::TaskPool &>(task_pool) = task_pool_util::TaskPool {};
      sessions.clear();
      input::testing::set_platform_input({});
    }

    /**
     * @brief Allocate a retained session and track its lease for teardown.
     * @param session_id Stable identity used for reconnects.
     * @param connection_id Receives the new connection lease.
     * @return Input state bound to the lease.
     */
    std::shared_ptr<input::input_t> allocate(const std::string &session_id, std::uint64_t &connection_id) {
      auto session = input::alloc(std::make_shared<safe::mail_raw_t>(), session_id, connection_id);
      sessions.emplace_back(session, connection_id);
      return session;
    }

    /**
     * @brief Execute real queued timers synchronously without starting worker threads.
     *
     * Tests drain the initial alloc() nudge before observing button counts.
     * The one-second bound rejects unexpected repeating or long-lived tasks.
     */
    void drain_tasks() {
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
      for (;;) {
        if (auto task = task_pool.pop()) {
          ASSERT_LT(std::chrono::steady_clock::now(), deadline);
          (*task)->run();
        } else if (auto next = task_pool.next()) {
          ASSERT_LT(*next, deadline);
          std::this_thread::sleep_until(*next);
        } else {
          return;
        }
      }
    }

    lvh::Mouse *mouse = nullptr;  ///< Observable fake mouse, owned by the platform backend.
    std::vector<std::pair<std::shared_ptr<input::input_t>, std::uint64_t>> sessions;  ///< Leases released at teardown.
  };
}  // namespace

TEST(InputConfigDefaults, AdvertisesNativePenWithoutRemappingRightAlt) {
  EXPECT_TRUE(config::input.keyboard);
  EXPECT_FALSE(config::input.key_rightalt_to_key_win);
  EXPECT_TRUE(config::input.mouse);
  EXPECT_TRUE(config::input.always_send_scancodes);
  EXPECT_TRUE(config::input.high_resolution_scrolling);
}

TEST_F(InputRetainedSessionTest, DisconnectSuspendsRatherThanDiscardingResumableRawTablet) {
  const std::string session_id = "resumed-tablet-client";
  std::uint64_t first_connection_id = 0;
  auto first = allocate(session_id, first_connection_id);
  ASSERT_TRUE(input::testing::handle_raw_hid(first, make_raw_hid_device_frame(7)));
  ASSERT_EQ(input::testing::raw_hid_generation(first), 7);

  std::uint64_t resumed_connection_id = 0;
  auto resumed = allocate(session_id, resumed_connection_id);
  ASSERT_EQ(first, resumed);
  ASSERT_GT(resumed_connection_id, first_connection_id);
  ASSERT_TRUE(input::testing::handle_raw_hid(resumed, make_raw_hid_device_frame(8)));
  ASSERT_EQ(input::testing::raw_hid_generation(resumed), 8);

  input::reset(first, first_connection_id);
  EXPECT_EQ(input::testing::raw_hid_generation(resumed), 8);

  input::reset(resumed, resumed_connection_id);
  EXPECT_EQ(input::testing::raw_hid_generation(resumed), 8);
}

TEST_F(InputRetainedSessionTest, OrphanReservationCleanupAndFreshLaunchKeepDesktopInput) {
  proc::proc_t reservation;
  ASSERT_EQ(reservation.execute(proc::desktop_app_id), 0);
  std::uint64_t lease = 0;
  auto first = allocate("plank-desktop", lease);
  ASSERT_TRUE(input::testing::handle_raw_hid(first, make_raw_hid_device_frame(7)));
  input::reset(first, lease);

  // Match a completed stream join: only the desktop owner may retain input.
  std::weak_ptr<input::input_t> retained = first;
  sessions.clear();
  first.reset();
  // These are the real reservation calls made by /launch after network loss.
  reservation.terminate();
  ASSERT_FALSE(retained.expired());
  ASSERT_EQ(reservation.execute(proc::desktop_app_id), 0);
  ASSERT_FALSE(retained.expired());
  std::uint64_t next_lease = 0;
  auto resumed = allocate("plank-desktop", next_lease);
  EXPECT_EQ(resumed, retained.lock());
  EXPECT_GT(next_lease, lease);
  EXPECT_EQ(input::testing::raw_hid_generation(resumed), 7);
  reservation.terminate();
}

TEST_F(InputRetainedSessionTest, FreshReservationCannotDestroyAnIdleDesktopTablet) {
  std::uint64_t lease = 0;
  auto first = allocate("plank-desktop", lease);
  ASSERT_TRUE(input::testing::handle_raw_hid(first, make_raw_hid_device_frame(7)));
  input::reset(first, lease);
  proc::proc_t reservation;
  ASSERT_EQ(reservation.running(), 0);
  ASSERT_EQ(reservation.execute(proc::desktop_app_id), 0);
  std::uint64_t next_lease = 0;
  auto resumed = allocate("plank-desktop", next_lease);
  EXPECT_EQ(first, resumed);
  EXPECT_EQ(input::testing::raw_hid_generation(resumed), 7);
  reservation.terminate();
}

TEST_F(InputRetainedSessionTest, DesktopShutdownReleasesInputAfterLastStreamReference) {
  std::uint64_t lease = 0;
  auto first = allocate("plank-desktop", lease);
  input::reset(first, lease);
  ASSERT_NO_FATAL_FAILURE(drain_tasks());
  std::weak_ptr<input::input_t> retained = first;
  sessions.clear();
  first.reset();
  ASSERT_FALSE(retained.expired());
  input::testing::set_platform_input({});
  EXPECT_TRUE(retained.expired());
}

TEST_F(InputRetainedSessionTest, DisconnectReleasesNormalizedPenWithoutViewport) {
  std::uint64_t lease = 0;
  auto session = allocate("normalized-pen-cleanup", lease);
  auto &context = platf::virtualhid::get_client_context(input::testing::client_context(session));
  ASSERT_NE(context.pen, nullptr);
  platf::pen_input_t pen {};
  pen.toolType = LI_TOOL_TYPE_PEN;
  pen.eventType = LI_TOUCH_EVENT_DOWN;
  pen.penButtons = LI_PEN_BUTTON_PRIMARY;
  pen.pressureOrDistance = 0.7F;
  platf::virtualhid::pen_update(context, {}, pen);
  ASSERT_EQ(context.pressed_pen_buttons.size(), 1);
  input::reset(session, lease);
  EXPECT_TRUE(context.pressed_pen_buttons.empty());
  EXPECT_EQ(context.pen->last_submitted_tool().transition, lvh::PointerTransition::cancel);
}

#ifdef PLANK_TRANSPORT
TEST_F(InputRetainedSessionTest, NativePenCancelDoesNotRequireDisplayGeometry) {
  std::uint64_t lease = 0;
  auto session = allocate("cancel-without-viewport", lease);
  auto &context = platf::virtualhid::get_client_context(input::testing::client_context(session));
  ASSERT_NE(context.pen, nullptr);
  platf::pen_input_t pen {};
  pen.toolType = LI_TOOL_TYPE_ERASER;
  pen.eventType = LI_TOUCH_EVENT_DOWN;
  pen.penButtons = LI_PEN_BUTTON_PRIMARY;
  pen.pressureOrDistance = 0.5F;
  platf::virtualhid::pen_update(context, {}, pen);
  std::array<std::uint8_t, PLANK_TRANSPORT_INPUT_PEN_SIZE> payload {};
  payload[0] = LI_TOUCH_EVENT_CANCEL_ALL;
  payload[1] = LI_TOOL_TYPE_UNKNOWN;
  ASSERT_TRUE(input::native(session, PLANK_TRANSPORT_INPUT_PEN, payload.data(), payload.size()));
  EXPECT_TRUE(context.pressed_pen_buttons.empty());
  EXPECT_EQ(context.pen->last_submitted_tool().transition, lvh::PointerTransition::cancel);
}
#endif

TEST_F(InputRetainedSessionTest, RebindAndCleanupCannotRaceInputDelivery) {
  using namespace std::chrono_literals;
  std::uint64_t lease = 0;
  auto session = allocate("input-serialization", lease);
  std::promise<void> locked, unlock, reset_started, rebind_started;
  auto gate = unlock.get_future();
  auto holder = std::async(std::launch::async, [&] {
    input::testing::with_input_lock([&] {
      locked.set_value();
      gate.wait();
    });
  });
  locked.get_future().wait();
  auto resetting = std::async(std::launch::async, [&] {
    reset_started.set_value();
    input::reset(session, lease);
  });
  auto rebinding = std::async(std::launch::async, [&] {
    rebind_started.set_value();
    std::uint64_t next_lease = 0;
    auto resumed = input::alloc(std::make_shared<safe::mail_raw_t>(), "input-serialization", next_lease);
    input::testing::handle_mouse_button(resumed, 1, false);
    return std::make_pair(resumed, next_lease);
  });
  reset_started.get_future().wait();
  rebind_started.get_future().wait();
  EXPECT_EQ(resetting.wait_for(30ms), std::future_status::timeout);
  EXPECT_EQ(rebinding.wait_for(30ms), std::future_status::timeout);
  unlock.set_value();
  holder.get();
  resetting.get();
  auto resumed = rebinding.get();
  sessions.push_back(resumed);
  EXPECT_EQ(session, resumed.first);
  EXPECT_GT(resumed.second, lease);
  // Regardless of which waiter acquires the lock first, old cleanup cannot
  // release the new lease's button after it has been pressed.
  EXPECT_TRUE(mouse->last_submitted_event().pressed);
}

TEST_F(InputRetainedSessionTest, LeftButtonReleaseIsImmediateAndNotRepeatedOnDisconnect) {
  const std::string session_id = "immediate-left-button-release";
  std::uint64_t connection_id = 0;
  auto session = allocate(session_id, connection_id);
  const auto before_press = mouse->submit_count();
  const auto next_task = task_pool.next();

  constexpr std::uint8_t left_button = 1;
  input::testing::handle_mouse_button(session, left_button, false);
  ASSERT_EQ(mouse->submit_count(), before_press + 1);
  EXPECT_EQ(mouse->last_submitted_event().kind, lvh::MouseEventKind::button);
  EXPECT_EQ(mouse->last_submitted_event().button, lvh::MouseButton::left);
  EXPECT_TRUE(mouse->last_submitted_event().pressed);

  // With the pool stopped, a deferred implementation cannot satisfy this.
  input::testing::handle_mouse_button(session, left_button, true);
  ASSERT_EQ(mouse->submit_count(), before_press + 2);
  EXPECT_EQ(mouse->last_submitted_event().kind, lvh::MouseEventKind::button);
  EXPECT_EQ(mouse->last_submitted_event().button, lvh::MouseButton::left);
  EXPECT_FALSE(mouse->last_submitted_event().pressed);
  EXPECT_EQ(task_pool.next(), next_task);
  input::reset(session, connection_id);
  EXPECT_EQ(mouse->submit_count(), before_press + 2);
}

TEST_F(InputRetainedSessionTest, RepeatedDisconnectDoesNotDuplicateButtonRelease) {
  std::uint64_t connection_id = 0;
  auto session = allocate("repeat-cleanup", connection_id);
  input::testing::handle_mouse_button(session, 1, false);
  const auto before_reset = mouse->submit_count();

  input::reset(session, connection_id);
  ASSERT_EQ(mouse->submit_count(), before_reset + 1);
  input::reset(session, connection_id);
  EXPECT_EQ(mouse->submit_count(), before_reset + 1);
  EXPECT_FALSE(mouse->last_submitted_event().pressed);
}

TEST_F(InputRetainedSessionTest, EmptyDisconnectDoesNotSynthesizeButtonEvents) {
  std::uint64_t connection_id = 0;
  auto session = allocate("empty-cleanup", connection_id);
  const auto before_reset = mouse->submit_count();
  input::reset(session, connection_id);
  input::reset(session, connection_id);
  EXPECT_EQ(mouse->submit_count(), before_reset);
}

TEST_F(InputRetainedSessionTest, DisconnectReleasesEachHeldMouseButtonOnce) {
  std::uint64_t connection_id = 0;
  auto session = allocate("held-buttons", connection_id);
  // Exercise left, middle and right separately so each release is observable.
  for (std::uint8_t button = 1; button <= 3; ++button) {
    SCOPED_TRACE(button);
    const auto before_press = mouse->submit_count();
    input::testing::handle_mouse_button(session, button, false);
    ASSERT_EQ(mouse->submit_count(), before_press + 1);
    const auto pressed_button = mouse->last_submitted_event().button;
    ASSERT_TRUE(mouse->last_submitted_event().pressed);
    input::reset(session, connection_id);
    ASSERT_EQ(mouse->submit_count(), before_press + 2);
    EXPECT_EQ(mouse->last_submitted_event().button, pressed_button);
    EXPECT_FALSE(mouse->last_submitted_event().pressed);
    input::reset(session, connection_id);
    EXPECT_EQ(mouse->submit_count(), before_press + 2);
  }
}

TEST_F(InputRetainedSessionTest, RapidLeftClicksRemainOrderedWithoutQueuedReleases) {
  std::uint64_t connection_id = 0;
  auto session = allocate("rapid-left-clicks", connection_id);
  ASSERT_NO_FATAL_FAILURE(drain_tasks());
  const auto before_press = mouse->submit_count();
  input::testing::handle_mouse_button(session, 1, false);
  ASSERT_EQ(mouse->submit_count(), before_press + 1);
  EXPECT_TRUE(mouse->last_submitted_event().pressed);
  input::testing::handle_mouse_button(session, 1, true);
  ASSERT_EQ(mouse->submit_count(), before_press + 2);
  EXPECT_FALSE(mouse->last_submitted_event().pressed);
  input::testing::handle_mouse_button(session, 1, false);
  ASSERT_EQ(mouse->submit_count(), before_press + 3);
  EXPECT_TRUE(mouse->last_submitted_event().pressed);
  EXPECT_FALSE(task_pool.next().has_value());
  input::testing::handle_mouse_button(session, 1, true);
  ASSERT_EQ(mouse->submit_count(), before_press + 4);
  EXPECT_FALSE(mouse->last_submitted_event().pressed);
  EXPECT_FALSE(task_pool.next().has_value());
  input::reset(session, connection_id);
  EXPECT_EQ(mouse->submit_count(), before_press + 4);
}

TEST_F(InputRetainedSessionTest, RightButtonRemainsHeldAfterLeftButtonRelease) {
  std::uint64_t connection_id = 0;
  auto session = allocate("left-then-right-drag", connection_id);
  const auto before_press = mouse->submit_count();
  const auto next_task = task_pool.next();
  input::testing::handle_mouse_button(session, 1, false);
  input::testing::handle_mouse_button(session, 1, true);
  ASSERT_EQ(mouse->submit_count(), before_press + 2);
  EXPECT_EQ(mouse->last_submitted_event().button, lvh::MouseButton::left);
  EXPECT_FALSE(mouse->last_submitted_event().pressed);

  // A real right press must remain down, not become a synthetic down/up pair.
  input::testing::handle_mouse_button(session, 3, false);
  ASSERT_EQ(mouse->submit_count(), before_press + 3);
  EXPECT_EQ(mouse->last_submitted_event().button, lvh::MouseButton::right);
  EXPECT_TRUE(mouse->last_submitted_event().pressed);
  input::testing::handle_mouse_button(session, 3, true);
  ASSERT_EQ(mouse->submit_count(), before_press + 4);
  EXPECT_FALSE(mouse->last_submitted_event().pressed);
  EXPECT_EQ(task_pool.next(), next_task);
  input::reset(session, connection_id);
  EXPECT_EQ(mouse->submit_count(), before_press + 4);
}

TEST_F(InputRetainedSessionTest, StaleDisconnectDoesNotReleaseResumedConnectionsButton) {
  std::uint64_t first_connection_id = 0;
  auto first = allocate("stale-cleanup", first_connection_id);
  input::reset(first, first_connection_id);
  std::uint64_t resumed_connection_id = 0;
  auto resumed = allocate("stale-cleanup", resumed_connection_id);
  ASSERT_EQ(first, resumed);
  ASSERT_GT(resumed_connection_id, first_connection_id);

  input::testing::handle_mouse_button(resumed, 1, false);
  const auto after_press = mouse->submit_count();
  input::reset(first, first_connection_id);
  EXPECT_EQ(mouse->submit_count(), after_press);
  EXPECT_TRUE(mouse->last_submitted_event().pressed);
  input::testing::handle_mouse_button(resumed, 1, true);
  EXPECT_EQ(mouse->submit_count(), after_press + 1);
  EXPECT_FALSE(mouse->last_submitted_event().pressed);
}

TEST_F(InputRetainedSessionTest, RebindBeforeOldDisconnectReleasesPreviousLease) {
  std::uint64_t lease = 0;
  auto session = allocate("rebind-before-disconnect", lease);
  input::testing::handle_mouse_button(session, 1, false);
  auto &context = platf::virtualhid::get_client_context(input::testing::client_context(session));
  platf::pen_input_t pen {};
  pen.toolType = LI_TOOL_TYPE_PEN;
  pen.eventType = LI_TOUCH_EVENT_DOWN;
  pen.pressureOrDistance = 0.6F;
  platf::virtualhid::pen_update(context, {}, pen);

  std::uint64_t next_lease = 0;
  auto resumed = allocate("rebind-before-disconnect", next_lease);
  ASSERT_EQ(session, resumed);
  EXPECT_FALSE(mouse->last_submitted_event().pressed);
  EXPECT_EQ(context.pen->last_submitted_tool().transition, lvh::PointerTransition::cancel);
  input::testing::handle_mouse_button(resumed, 1, false);
  platf::virtualhid::pen_update(context, {}, pen);
  input::reset(session, lease);
  EXPECT_TRUE(mouse->last_submitted_event().pressed);
  EXPECT_EQ(context.pen->last_submitted_tool().transition, lvh::PointerTransition::update);
}

TEST_F(InputRetainedSessionTest, ReconnectKeepsNewDragHeldUntilItsOwnRelease) {
  std::uint64_t first_connection_id = 0;
  auto first = allocate("reconnect-release", first_connection_id);
  ASSERT_NO_FATAL_FAILURE(drain_tasks());
  const auto before_press = mouse->submit_count();
  input::testing::handle_mouse_button(first, 1, false);
  input::testing::handle_mouse_button(first, 1, true);
  ASSERT_EQ(mouse->submit_count(), before_press + 2);
  input::reset(first, first_connection_id);
  ASSERT_EQ(mouse->submit_count(), before_press + 2);

  std::uint64_t resumed_connection_id = 0;
  auto resumed = allocate("reconnect-release", resumed_connection_id);
  ASSERT_EQ(first, resumed);
  ASSERT_GT(resumed_connection_id, first_connection_id);
  input::testing::handle_mouse_button(resumed, 1, false);
  ASSERT_EQ(mouse->submit_count(), before_press + 3);
  EXPECT_TRUE(mouse->last_submitted_event().pressed);
  ASSERT_NO_FATAL_FAILURE(drain_tasks());
  // Only alloc()'s two movement events may run, never an old button release.
  EXPECT_EQ(mouse->submit_count(), before_press + 5);
  input::testing::handle_mouse_button(resumed, 1, true);
  EXPECT_EQ(mouse->submit_count(), before_press + 6);
  EXPECT_EQ(mouse->last_submitted_event().kind, lvh::MouseEventKind::button);
  EXPECT_FALSE(mouse->last_submitted_event().pressed);
  input::reset(resumed, resumed_connection_id);
  EXPECT_EQ(mouse->submit_count(), before_press + 6);
}

TEST_F(InputRetainedSessionTest, ConsumesNumLockWithoutChangingNumericKeypadIdentity) {
  const std::string session_id = "always-on-num-lock";
  std::uint64_t connection_id = 0;
  auto session = allocate(session_id, connection_id);

  input::testing::handle_keyboard(session, 0x61, false);
  EXPECT_EQ(input::testing::last_keyboard_code(), 0x61);

  input::testing::handle_keyboard(session, 0x90, false);
  input::testing::handle_keyboard(session, 0x90, true);
  EXPECT_EQ(input::testing::last_keyboard_code(), 0x61);
}

TEST_F(InputRetainedSessionTest, ExactRawTabletSuppressesNormalizedFallbackUntilDetach) {
  if (!raw_hid::available()) {
    GTEST_SKIP() << "/dev/uhid is unavailable to the test process";
  }

  const std::string session_id = "exclusive-raw-tablet";
  std::uint64_t connection_id = 0;
  auto session = allocate(session_id, connection_id);
  ASSERT_TRUE(input::testing::normalized_pen_enabled(session));

  constexpr std::uint16_t generation = 11;
  ASSERT_TRUE(input::testing::handle_raw_hid(session, make_raw_hid_device_frame(generation, 0x0358)));
  EXPECT_TRUE(input::testing::normalized_pen_enabled(session));

  // Minimal valid HID application collection. Backend ownership changes from
  // the generic fallback to raw HID only after all descriptors are accepted
  // and exact UHID endpoints exist.
  const std::uint8_t descriptor[] {
    0x05, 0x01,  // Usage Page (Generic Desktop)
    0x09, 0x02,  // Usage (Mouse)
    0xa1, 0x01,  // Collection (Application)
    0xc0,  // End Collection
  };
  ASSERT_TRUE(input::testing::handle_raw_hid(session, make_raw_hid_frame(
                                                        PLANK_RAW_HID_DESCRIPTOR,
                                                        0,
                                                        generation,
                                                        descriptor,
                                                        sizeof(descriptor)
                                                      )));
  EXPECT_FALSE(input::testing::normalized_pen_enabled(session));

  ASSERT_TRUE(input::testing::handle_raw_hid(session, make_raw_hid_frame(
                                                        PLANK_RAW_HID_SUSPEND,
                                                        0,
                                                        generation,
                                                        nullptr,
                                                        0
                                                      )));
  EXPECT_FALSE(input::testing::normalized_pen_enabled(session));

  ASSERT_TRUE(input::testing::handle_raw_hid(session, make_raw_hid_frame(
                                                        PLANK_RAW_HID_DETACH,
                                                        0,
                                                        generation,
                                                        nullptr,
                                                        0
                                                      )));
  EXPECT_TRUE(input::testing::normalized_pen_enabled(session));
}

TEST_F(InputRetainedSessionTest, NormalizedPenReleasesRetainedRawTabletEndpoints) {
  if (!raw_hid::available()) {
    GTEST_SKIP() << "/dev/uhid is unavailable to the test process";
  }

  const std::string session_id = "raw-to-normalized-tablet";
  std::uint64_t connection_id = 0;
  auto session = allocate(session_id, connection_id);

  constexpr std::uint16_t generation = 12;
  ASSERT_TRUE(input::testing::handle_raw_hid(session, make_raw_hid_device_frame(generation, 0x0357)));
  const std::uint8_t descriptor[] {
    0x05, 0x01,
    0x09, 0x02,
    0xa1, 0x01,
    0xc0,
  };
  ASSERT_TRUE(input::testing::handle_raw_hid(session, make_raw_hid_frame(
                                                        PLANK_RAW_HID_DESCRIPTOR,
                                                        0,
                                                        generation,
                                                        descriptor,
                                                        sizeof(descriptor)
                                                      )));
  ASSERT_FALSE(input::testing::normalized_pen_enabled(session));
  ASSERT_EQ(input::testing::raw_hid_generation(session), generation);

  input::testing::select_normalized_pen(session);

  EXPECT_TRUE(input::testing::normalized_pen_enabled(session));
  EXPECT_EQ(input::testing::raw_hid_generation(session), 0);
}
