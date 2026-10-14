/**
 * @file src/raw_hid_contact.cpp
 * @brief Read, release and verify retained tablet contact without device resets.
 */
#include "raw_hid_contact.h"

#ifdef __linux__
  #include <array>
  #include <cerrno>
  #include <linux/input.h>
  #include <span>
  #include <sys/ioctl.h>
  #include <unistd.h>

namespace raw_hid {
  namespace {
    constexpr std::size_t bits_per_long = sizeof(unsigned long) * 8;  ///< Kernel bitmap word size.
    constexpr int max_attempts = 4;  ///< Maximum attempts after interrupted queries/writes.
    constexpr int max_mt_slots = 64;  ///< Bound on multitouch allocation.

    /**
     * @brief Test a bit in an evdev bitmap.
     * @param bits Bitmap.
     * @param bit Index.
     * @return Set state.
     */
    bool test_bit(std::span<const unsigned long> bits, unsigned int bit) {
      return bit / bits_per_long < bits.size() && ((bits[bit / bits_per_long] >> (bit % bits_per_long)) & 1UL) != 0;
    }

    /**
     * @brief Identify proximity keys.
     * @param code Key.
     * @param multitouch Slot capability.
     * @return Whether to preserve the key.
     */
    bool is_proximity_key(std::uint16_t code, bool multitouch) {
      switch (code) {
        case BTN_TOOL_PEN:
        case BTN_TOOL_RUBBER:
        case BTN_TOOL_BRUSH:
        case BTN_TOOL_PENCIL:
        case BTN_TOOL_AIRBRUSH:
        case BTN_TOOL_MOUSE:
        case BTN_TOOL_LENS:
          return true;
        case BTN_TOOL_FINGER:
        case BTN_TOOL_DOUBLETAP:
        case BTN_TOOL_TRIPLETAP:
        case BTN_TOOL_QUADTAP:
        case BTN_TOOL_QUINTTAP:
          return !multitouch;
        default:
          return false;
      }
    }

    /**
     * @brief Query input state with a finite EINTR retry budget.
     * @param fd Endpoint.
     * @param request ioctl command.
     * @param data Destination.
     * @param io Syscall boundary.
     * @return Zero or captured errno.
     */
    int query(int fd, unsigned long request, void *data, const contact_io_t &io) {
      for (int attempt = 0; attempt < max_attempts; ++attempt) {
        if (io.query(fd, request, data) >= 0) {
          return 0;
        }
        const int error = errno;
        if (error != EINTR || attempt == max_attempts - 1) {
          return error != 0 ? error : EIO;
        }
      }
      return EINTR;
    }

    /**
     * @brief Read all supported contact state, failing rather than guessing idle.
     * @param fd Endpoint.
     * @param state Output snapshot.
     * @param io Syscall boundary.
     * @return Success or the failed query and its errno.
     */
    contact_release_result_t read_node_state(int fd, input_node_state_t &state, const contact_io_t &io) {
      std::array<unsigned long, (KEY_CNT + bits_per_long - 1) / bits_per_long> keys {};
      if (const int error = query(fd, EVIOCGKEY(sizeof(keys)), keys.data(), io)) {
        return {error, "read keys"};
      }
      for (unsigned int code = 0; code < KEY_CNT; ++code) {
        if (test_bit(keys, code)) {
          state.held_keys.push_back(static_cast<std::uint16_t>(code));
        }
      }
      std::array<unsigned long, (ABS_CNT + bits_per_long - 1) / bits_per_long> axes {};
      if (const int error = query(fd, EVIOCGBIT(EV_ABS, sizeof(axes)), axes.data(), io)) {
        return {error, "read axes"};
      }
      input_absinfo info {};
      if (test_bit(axes, ABS_PRESSURE)) {
        if (const int error = query(fd, EVIOCGABS(ABS_PRESSURE), &info, io)) {
          return {error, "read pressure"};
        }
        state.pressure = info.value;
      }
      if (test_bit(axes, ABS_MT_SLOT) && test_bit(axes, ABS_MT_TRACKING_ID)) {
        if (const int error = query(fd, EVIOCGABS(ABS_MT_SLOT), &info, io)) {
          return {error, "read slot bounds"};
        }
        if (info.minimum != 0 || info.maximum < 0 || info.maximum >= max_mt_slots ||
            info.value < 0 || info.value > info.maximum) {
          return {EOVERFLOW, "validate slot bounds"};
        }
        std::vector<std::int32_t> request(static_cast<std::size_t>(info.maximum) + 2);
        request[0] = ABS_MT_TRACKING_ID;
        if (const int error = query(fd, EVIOCGMTSLOTS(request.size() * sizeof(std::int32_t)), request.data(), io)) {
          return {error, "read contacts"};
        }
        state.mt_current_slot = info.value;
        state.mt_tracking_ids.assign(request.begin() + 1, request.end());
      }
      return {};
    }

    /**
     * @brief Finish an event batch without losing its final SYN_REPORT.
     * @param fd Endpoint.
     * @param plan Release events.
     * @param io Syscall boundary.
     * @return Zero or captured errno; malformed/zero progress is EIO.
     */
    int write_release(int fd, const std::vector<release_event_t> &plan, const contact_io_t &io) {
      std::vector<input_event> events(plan.size());
      for (std::size_t index = 0; index < plan.size(); ++index) {
        events[index].type = plan[index].type;
        events[index].code = plan[index].code;
        events[index].value = plan[index].value;
      }
      std::size_t offset = 0;
      int interrupts_left = max_attempts - 1;
      while (offset < events.size()) {
        const auto remaining = (events.size() - offset) * sizeof(input_event);
        const auto written = io.write(fd, events.data() + offset, remaining);
        if (written < 0) {
          const int error = errno;
          if (error == EINTR && interrupts_left-- > 0) {
            continue;
          }
          return error != 0 ? error : EIO;
        }
        if (written == 0 || static_cast<std::size_t>(written) > remaining || written % sizeof(input_event) != 0) {
          return EIO;
        }
        offset += static_cast<std::size_t>(written) / sizeof(input_event);
      }
      return 0;
    }
  }  // namespace

  std::vector<release_event_t> plan_contact_release(const input_node_state_t &state) {
    std::vector<release_event_t> events;
    const bool multitouch = state.mt_current_slot.has_value();
    if (multitouch) {
      bool moved_slot = false;
      for (std::size_t slot = 0; slot < state.mt_tracking_ids.size(); ++slot) {
        if (state.mt_tracking_ids[slot] < 0) {
          continue;
        }
        events.push_back({EV_ABS, ABS_MT_SLOT, static_cast<std::int32_t>(slot)});
        events.push_back({EV_ABS, ABS_MT_TRACKING_ID, -1});
        moved_slot = true;
      }
      if (moved_slot) {
        events.push_back({EV_ABS, ABS_MT_SLOT, *state.mt_current_slot});
      }
    }
    for (const auto code : state.held_keys) {
      if (!is_proximity_key(code, multitouch)) {
        events.push_back({EV_KEY, code, 0});
      }
    }
    if (state.pressure.value_or(0) != 0) {
      events.push_back({EV_ABS, ABS_PRESSURE, 0});
    }
    if (!events.empty()) {
      events.push_back({EV_SYN, SYN_REPORT, 0});
    }
    return events;
  }

  const contact_io_t &system_contact_io() {
    static const contact_io_t io {
      [](int fd, unsigned long request, void *data) { return ioctl(fd, request, data); },
      ::write,
    };
    return io;
  }

  contact_release_result_t release_node_contacts(int fd, const contact_io_t &io) {
    input_node_state_t state;
    if (const auto result = read_node_state(fd, state, io); result.error != 0) {
      return result;
    }
    const auto plan = plan_contact_release(state);
    if (plan.empty()) {
      return {};
    }
    if (const int error = write_release(fd, plan, io)) {
      return {error, "write releases"};
    }
    input_node_state_t remaining;
    if (const auto result = read_node_state(fd, remaining, io); result.error != 0) {
      return {result.error, "verify releases"};
    }
    if (!plan_contact_release(remaining).empty()) {
      return {EBUSY, "verify releases"};
    }
    return {0, nullptr, true};
  }
}  // namespace raw_hid
#endif
