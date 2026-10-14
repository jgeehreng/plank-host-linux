#include <gtest/gtest.h>
#include "src/raw_hid_contact.h"
#ifdef __linux__
#include <linux/input.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <deque>
#include <sys/ioctl.h>
#endif

#ifdef __linux__
TEST(RawHidTablet, ReleasesPenContactWithoutLeavingProximity) {
  raw_hid::input_node_state_t pen;
  pen.held_keys = {BTN_TOOL_PEN, BTN_TOUCH, BTN_STYLUS};
  pen.pressure = 4096;

  const std::vector<raw_hid::release_event_t> expected {
    {EV_KEY, BTN_TOUCH, 0},
    {EV_KEY, BTN_STYLUS, 0},
    {EV_ABS, ABS_PRESSURE, 0},
    {EV_SYN, SYN_REPORT, 0},
  };
  EXPECT_EQ(raw_hid::plan_contact_release(pen), expected);
}

TEST(RawHidTablet, KeepsToolProximityOnPenAndPadNodes) {
  raw_hid::input_node_state_t tools;
  tools.held_keys = {
    BTN_TOOL_PEN,
    BTN_TOOL_RUBBER,
    BTN_TOOL_BRUSH,
    BTN_TOOL_PENCIL,
    BTN_TOOL_AIRBRUSH,
    BTN_TOOL_FINGER,
    BTN_TOOL_MOUSE,
    BTN_TOOL_LENS,
  };
  tools.pressure = 0;

  EXPECT_TRUE(raw_hid::plan_contact_release(tools).empty());
}

TEST(RawHidTablet, ReleasesHeldPadKeys) {
  raw_hid::input_node_state_t pad;
  pad.held_keys = {BTN_0, BTN_5, BTN_TOOL_FINGER};

  const std::vector<raw_hid::release_event_t> expected {
    {EV_KEY, BTN_0, 0},
    {EV_KEY, BTN_5, 0},
    {EV_SYN, SYN_REPORT, 0},
  };
  EXPECT_EQ(raw_hid::plan_contact_release(pad), expected);
}

TEST(RawHidTablet, EndsActiveTouchesAndRestoresCurrentSlot) {
  raw_hid::input_node_state_t touch;
  touch.mt_current_slot = 2;
  touch.mt_tracking_ids = {14, -1, 15};
  touch.held_keys = {BTN_TOUCH, BTN_TOOL_DOUBLETAP};

  const std::vector<raw_hid::release_event_t> expected {
    {EV_ABS, ABS_MT_SLOT, 0},
    {EV_ABS, ABS_MT_TRACKING_ID, -1},
    {EV_ABS, ABS_MT_SLOT, 2},
    {EV_ABS, ABS_MT_TRACKING_ID, -1},
    {EV_ABS, ABS_MT_SLOT, 2},
    {EV_KEY, BTN_TOUCH, 0},
    {EV_KEY, BTN_TOOL_DOUBLETAP, 0},
    {EV_SYN, SYN_REPORT, 0},
  };
  EXPECT_EQ(raw_hid::plan_contact_release(touch), expected);
}

TEST(RawHidTablet, ReleasesResidualPressureAlone) {
  raw_hid::input_node_state_t pen;
  pen.held_keys = {BTN_TOOL_PEN};
  pen.pressure = 12;

  const std::vector<raw_hid::release_event_t> expected {
    {EV_ABS, ABS_PRESSURE, 0},
    {EV_SYN, SYN_REPORT, 0},
  };
  EXPECT_EQ(raw_hid::plan_contact_release(pen), expected);
}

TEST(RawHidTablet, PlansNothingWithoutHeldContact) {
  raw_hid::input_node_state_t idle;
  idle.pressure = 0;
  idle.mt_current_slot = 0;
  idle.mt_tracking_ids = {-1, -1};

  EXPECT_TRUE(raw_hid::plan_contact_release(idle).empty());
  EXPECT_TRUE(raw_hid::plan_contact_release({}).empty());
}

namespace {
  /** @brief In-memory evdev boundary; tests never access a real input device. */
  class RawHidContactIo: public testing::Test {
  protected:
    raw_hid::input_node_state_t state;
    std::vector<input_event> written;
    std::deque<ssize_t> write_results;
    std::size_t write_limit = SIZE_MAX;
    unsigned int query_count = 0, write_count = 0, failed_count = 0;
    unsigned int fail_request = 0;
    int fail_errno = EINTR, failures_left = 0;
    bool fail_after_write = false, ignore_releases = false;
    std::optional<input_absinfo> slot_bounds;
    static inline RawHidContactIo *current = nullptr;

    void SetUp() override {
      current = this;
      state.held_keys = {BTN_TOOL_PEN, BTN_TOUCH, BTN_STYLUS};
      state.pressure = 4096;
    }

    void TearDown() override {
      current = nullptr;
    }

    /** @brief Populate a kernel bitmap. @param data Destination. @param bit Index. */
    static void set_bit(void *data, unsigned int bit) {
      auto *words = static_cast<unsigned long *>(data);
      words[bit / (sizeof(unsigned long) * 8)] |= 1UL << (bit % (sizeof(unsigned long) * 8));
    }

    /** @brief Emulate evdev queries and deterministic failures. */
    static int query(int, unsigned long request, void *data) {
      auto &self = *current;
      ++self.query_count;
      if (_IOC_NR(request) == self.fail_request && self.failures_left > 0 &&
          (!self.fail_after_write || self.write_count != 0)) {
        --self.failures_left;
        ++self.failed_count;
        errno = self.fail_errno;
        return -1;
      }
      const auto &state = self.state;
      if (_IOC_NR(request) == _IOC_NR(EVIOCGKEY(0))) {
        for (const auto code : state.held_keys) {
          set_bit(data, code);
        }
      } else if (_IOC_NR(request) == _IOC_NR(EVIOCGBIT(EV_ABS, 0))) {
        if (state.pressure) {
          set_bit(data, ABS_PRESSURE);
        }
        if (state.mt_current_slot) {
          set_bit(data, ABS_MT_SLOT);
          set_bit(data, ABS_MT_TRACKING_ID);
        }
      } else if (request == EVIOCGABS(ABS_PRESSURE)) {
        static_cast<input_absinfo *>(data)->value = *state.pressure;
      } else if (request == EVIOCGABS(ABS_MT_SLOT)) {
        auto &info = *static_cast<input_absinfo *>(data);
        info = self.slot_bounds.value_or(input_absinfo {*state.mt_current_slot, 0,
          static_cast<int>(state.mt_tracking_ids.size()) - 1, 0, 0, 0});
      } else if (_IOC_NR(request) == _IOC_NR(EVIOCGMTSLOTS(0))) {
        std::copy(state.mt_tracking_ids.begin(), state.mt_tracking_ids.end(), static_cast<std::int32_t *>(data) + 1);
      } else {
        ADD_FAILURE() << "Unexpected ioctl";
        errno = EINVAL;
        return -1;
      }
      return 0;
    }

    /** @brief Apply exactly the accepted prefix of a write, as evdev would. */
    static ssize_t write(int, const void *data, std::size_t size) {
      auto &self = *current;
      ++self.write_count;
      ssize_t result = static_cast<ssize_t>(std::min(size, self.write_limit));
      if (!self.write_results.empty()) {
        result = self.write_results.front();
        self.write_results.pop_front();
      }
      if (result < 0) {
        errno = static_cast<int>(-result);
        return -1;
      }
      if (static_cast<std::size_t>(result) > size || result % sizeof(input_event) != 0) {
        return result;
      }
      const auto *events = static_cast<const input_event *>(data);
      for (std::size_t i = 0; i < static_cast<std::size_t>(result) / sizeof(input_event); ++i) {
        const auto &event = events[i];
        self.written.push_back(event);
        if (self.ignore_releases) {
          continue;
        }
        if (event.type == EV_KEY) {
          std::erase(self.state.held_keys, event.code);
        } else if (event.type == EV_ABS && event.code == ABS_PRESSURE) {
          self.state.pressure = event.value;
        } else if (event.type == EV_ABS && event.code == ABS_MT_SLOT) {
          self.state.mt_current_slot = event.value;
        } else if (event.type == EV_ABS && event.code == ABS_MT_TRACKING_ID) {
          self.state.mt_tracking_ids.at(*self.state.mt_current_slot) = event.value;
        }
      }
      return result;
    }

    /** @brief Run the actual production cleanup against the fake boundary. */
    raw_hid::contact_release_result_t release() {
      return raw_hid::release_node_contacts(-1, {query, write});
    }
  };
}

TEST_F(RawHidContactIo, ReleasesAndVerifiesPenKeepingProximity) {
  const auto result = release();
  EXPECT_EQ(result.error, 0);
  EXPECT_TRUE(result.released);
  EXPECT_EQ(state.held_keys, (std::vector<std::uint16_t> {BTN_TOOL_PEN}));
  EXPECT_EQ(state.pressure, 0);
  ASSERT_EQ(written.size(), 4U);
  EXPECT_EQ(written.back().type, EV_SYN);
}

TEST_F(RawHidContactIo, IdleAndKeyOnlyNodesAreNotReadFailures) {
  state = {};
  EXPECT_EQ(release().error, 0);
  EXPECT_EQ(write_count, 0U);
  state.held_keys = {BTN_0};
  EXPECT_TRUE(release().released);
  EXPECT_TRUE(state.held_keys.empty());
  EXPECT_FALSE(release().released);
}

TEST_F(RawHidContactIo, RetriesInterruptedReadsForEveryStateComponent) {
  for (const auto request : std::array<unsigned long, 5> {EVIOCGKEY(0), EVIOCGBIT(EV_ABS, 0), EVIOCGABS(ABS_PRESSURE),
         EVIOCGABS(ABS_MT_SLOT), EVIOCGMTSLOTS(0)}) {
    state.held_keys = {BTN_TOUCH, BTN_TOOL_DOUBLETAP};
    state.pressure = 1500;
    state.mt_current_slot = 1;
    state.mt_tracking_ids = {12, 13};
    fail_request = _IOC_NR(request);
    failures_left = 1;
    EXPECT_TRUE(release().released) << request;
    EXPECT_EQ(failures_left, 0);
  }
  EXPECT_EQ(failed_count, 5U);
}

TEST_F(RawHidContactIo, FailedReadsAreNotReportedAsIdleOrPartiallyReleased) {
  for (const auto request : std::array<unsigned long, 5> {EVIOCGKEY(0), EVIOCGBIT(EV_ABS, 0), EVIOCGABS(ABS_PRESSURE),
         EVIOCGABS(ABS_MT_SLOT), EVIOCGMTSLOTS(0)}) {
    state.mt_current_slot = 0;
    state.mt_tracking_ids = {12};
    fail_request = _IOC_NR(request);
    fail_errno = ENODEV;
    failures_left = 1;
    const auto result = release();
    EXPECT_EQ(result.error, ENODEV);
    EXPECT_NE(result.operation, nullptr);
    EXPECT_FALSE(result.released);
    EXPECT_EQ(write_count, 0U);
    EXPECT_EQ(state.pressure, 4096);
  }
}

TEST_F(RawHidContactIo, EndlessReadInterruptionsStopAfterFourAttempts) {
  fail_request = _IOC_NR(EVIOCGKEY(0));
  failures_left = 100;
  const auto result = release();
  EXPECT_EQ(result.error, EINTR);
  EXPECT_EQ(query_count, 4U);
  EXPECT_EQ(write_count, 0U);
}

TEST_F(RawHidContactIo, ResumesPartialWritesIncludingTheFinalSync) {
  write_results = {-EINTR, sizeof(input_event), -EINTR, sizeof(input_event)};
  EXPECT_TRUE(release().released);
  EXPECT_EQ(write_count, 5U);
  ASSERT_EQ(written.size(), 4U);
  EXPECT_EQ(written[0].code, BTN_TOUCH);
  EXPECT_EQ(written[1].code, BTN_STYLUS);
  EXPECT_EQ(written.back().type, EV_SYN);
}

TEST_F(RawHidContactIo, WriteInterruptionsHaveAFixedBudget) {
  write_results = {-EINTR, -EINTR, -EINTR, -EINTR, sizeof(input_event)};
  const auto result = release();
  EXPECT_EQ(result.error, EINTR);
  EXPECT_FALSE(result.released);
  EXPECT_EQ(write_count, 4U);
  EXPECT_EQ(write_results.size(), 1U);
}

TEST_F(RawHidContactIo, RejectsZeroMisalignedAndImpossibleWriteProgress) {
  for (const ssize_t result : {0, 1, 100000}) {
    write_results = {result};
    const auto cleanup = release();
    EXPECT_EQ(cleanup.error, EIO);
    EXPECT_FALSE(cleanup.released);
  }
  EXPECT_EQ(write_count, 3U);
}

TEST_F(RawHidContactIo, PermanentAndWouldBlockWriteFailuresAreBounded) {
  for (const int error : {EAGAIN, ENODEV, EACCES}) {
    write_results = {-error};
    const auto result = release();
    EXPECT_EQ(result.error, error);
    EXPECT_STREQ(result.operation, "write releases");
    EXPECT_FALSE(result.released);
  }
  EXPECT_EQ(write_count, 3U);
}

TEST_F(RawHidContactIo, DoesNotClaimSuccessWhenInjectionHadNoEffect) {
  ignore_releases = true;
  const auto result = release();
  EXPECT_EQ(result.error, EBUSY);
  EXPECT_STREQ(result.operation, "verify releases");
  EXPECT_FALSE(result.released);
}

TEST_F(RawHidContactIo, DoesNotClaimSuccessWhenVerificationFails) {
  fail_request = _IOC_NR(EVIOCGKEY(0));
  fail_errno = ENODEV;
  failures_left = 1;
  fail_after_write = true;
  const auto result = release();
  EXPECT_EQ(result.error, ENODEV);
  EXPECT_STREQ(result.operation, "verify releases");
  EXPECT_FALSE(result.released);
}

TEST_F(RawHidContactIo, ReleasesEveryBoundedSlotEvenWithSingleEventWrites) {
  state.held_keys = {BTN_TOUCH, BTN_TOOL_DOUBLETAP};
  state.mt_current_slot = 37;
  state.mt_tracking_ids.assign(64, 42);
  write_limit = sizeof(input_event);
  EXPECT_TRUE(release().released);
  EXPECT_EQ(state.mt_current_slot, 37);
  EXPECT_EQ(state.mt_tracking_ids, std::vector<std::int32_t>(64, -1));
  EXPECT_TRUE(state.held_keys.empty());
  EXPECT_EQ(written.back().type, EV_SYN);
}

TEST_F(RawHidContactIo, InvalidSlotBoundsFailWithoutWriting) {
  state.mt_current_slot = 0;
  state.mt_tracking_ids = {42};
  for (const auto info : {input_absinfo {0, 0, 64, 0, 0, 0}, {0, 1, 2, 0, 0, 0},
         {-1, 0, 1, 0, 0, 0}, {2, 0, 1, 0, 0, 0}, {0, 0, -1, 0, 0, 0}}) {
    slot_bounds = info;
    EXPECT_EQ(release().error, EOVERFLOW);
  }
  EXPECT_EQ(write_count, 0U);
}
#endif
