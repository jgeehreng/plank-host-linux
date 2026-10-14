/**
 * @file src/raw_hid_contact.h
 * @brief Bounded contact cleanup for retained Linux raw tablet endpoints.
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <vector>

namespace raw_hid {
  /**
   * @brief Input-core state of one mirrored tablet input node.
   */
  struct input_node_state_t {
    std::vector<std::uint16_t> held_keys;  ///< Key and button codes currently down.
    std::optional<std::int32_t> pressure;  ///< Supported ABS_PRESSURE value.
    std::optional<std::int32_t> mt_current_slot;  ///< Current multitouch slot.
    std::vector<std::int32_t> mt_tracking_ids;  ///< Tracking ID of each slot.
  };

  /**
   * @brief One event injected into a mirrored tablet input node.
   */
  struct release_event_t {
    std::uint16_t type;  ///< Linux input event type.
    std::uint16_t code;  ///< Linux input event code.
    std::int32_t value;  ///< Event value.
    bool operator==(const release_event_t &) const = default;
  };

  /**
   * @brief End held contact without modifying tool proximity or device identity.
   * @param state Validated input-core state.
   * @return Release events ending in SYN_REPORT, or none when idle.
   */
  std::vector<release_event_t> plan_contact_release(const input_node_state_t &state);
}  // namespace raw_hid

#ifdef __linux__
  #include <sys/types.h>

namespace raw_hid {
  /**
   * @brief Syscall boundary shared by production cleanup and fault tests.
   */
  struct contact_io_t {
    int (*query)(int, unsigned long, void *);  ///< evdev ioctl operation.
    ssize_t (*write)(int, const void *, std::size_t);  ///< evdev event write.
  };

  /**
   * @brief Cleanup outcome; an unreadable node is never treated as idle.
   */
  struct contact_release_result_t {
    int error = 0;  ///< Captured errno, or zero for verified success/idle.
    const char *operation = nullptr;  ///< Failed operation; static diagnostic text.
    bool released = false;  ///< True only after writing and verifying release.
  };

  /**
   * @brief Return the real evdev syscall boundary.
   * @return Immutable production operations.
   */
  const contact_io_t &system_contact_io();

  /**
   * @brief Read, release and verify a suspended endpoint with bounded retries.
   *
   * Caller holds the tablet lock and has stopped raw report delivery. There is
   * no deferred retry that could release a new stroke after transport resumes.
   * Each query permits at most four attempts; writes permit bounded EINTR
   * retries plus at most one successful write per planned event. No sleeps.
   *
   * @param fd Matching retained evdev endpoint, opened nonblocking for writing.
   * @param io Injectable operating-system boundary.
   * @return Verified idle/released state or the exact failed operation.
   */
  contact_release_result_t release_node_contacts(int fd, const contact_io_t &io = system_contact_io());
}  // namespace raw_hid
#endif
