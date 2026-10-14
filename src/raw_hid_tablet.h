/**
 * @file src/raw_hid_tablet.h
 * @brief Desktop-owned raw HID tablet redirection with per-stream transport bindings.
 */
#pragma once
#include "raw_hid_contact.h"
#include "thread_safe.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace raw_hid {
  using feedback_queue_t = safe::mail_raw_t::queue_t<std::vector<std::uint8_t>>;

  /**
   * @brief Check whether this process can create Linux UHID devices.
   *
   * @return True when raw tablet redirection can be offered to a client.
   */
  bool available();

  /**
   * @brief Owns virtual HID interfaces retained across desktop stream connections.
   */
  class tablet_t {
  public:
    /**
     * @brief Create an empty tablet redirector.
     *
     * @param feedback_queue Queue carrying host control requests to the client.
     */
    explicit tablet_t(feedback_queue_t feedback_queue);

    /**
     * @brief Destroy all virtual interfaces owned by this tablet redirector.
     */
    ~tablet_t();

    tablet_t(const tablet_t &) = delete;
    tablet_t &operator=(const tablet_t &) = delete;

    /**
     * @brief Process one complete PLANK raw HID wire frame.
     *
     * @param frame Header and payload received from the authenticated client.
     * @return True when the frame was valid and accepted.
     */
    bool handle(const std::vector<std::uint8_t> &frame);

    /**
     * @brief Bind outbound control messages to a resumed session mailbox.
     *
     * @param feedback_queue Queue carrying host control requests to the client.
     */
    void rebind(feedback_queue_t feedback_queue);

    /**
     * @brief Suspend transport delivery while retaining stable UHID endpoints.
     *
     * Held pen, button, key and touch contact on the retained endpoints is
     * released so a suspend mid-stroke cannot leave a stuck contact. A resumed
     * client must present the same device identity and report descriptors
     * before input delivery is enabled again.
     */
    void suspend();

    /**
     * @brief Destroy every virtual interface and discard pending state.
     */
    void reset();

    /**
     * @brief Return whether exact raw-HID endpoints currently exist.
     *
     * Suspended endpoints remain present so their XInput identities survive a
     * resumable focus or transport transition.
     *
     * @return True when one or more UHID endpoints are retained.
     */
    bool has_endpoints();

#ifdef SUNSHINE_TESTS
    /**
     * @brief Return the active generation for lifecycle regression tests.
     */
    std::uint16_t active_generation();

    /**
     * @brief Return the endpoint creation epoch for reconnect regression tests.
     */
    std::uint64_t endpoint_epoch();

    /** @brief Replace contact cleanup for deterministic syscall-failure tests. */
    void set_contact_cleanup_for_test(std::function<bool()> cleanup);
#endif

  private:
    class impl_t;
    std::unique_ptr<impl_t> impl_;  ///< Platform implementation and session state.
  };
}  // namespace raw_hid
