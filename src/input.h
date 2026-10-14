/**
 * @file src/input.h
 * @brief Declarations for keyboard, mouse, pen, and raw-HID input handling.
 */
#pragma once

// standard includes
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

// local includes
#include "platform/common.h"
#include "thread_safe.h"

#ifdef SUNSHINE_TESTS
namespace raw_hid {
  class tablet_t;
}
#endif

namespace input {
  struct input_t;

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param input Raw input packet to format for logging.
   */
  void print(void *input);
  /**
   * @brief Reset stream input state after a client disconnect or shutdown.
   *
   * @param input Shared stream input state to reset.
   * @param connection_id Lease assigned when this stream bound the retained state.
   */
  void reset(std::shared_ptr<input_t> &input, std::uint64_t connection_id);

  /**
   * @brief Queue a raw input message for platform passthrough.
   */
  void passthrough(std::shared_ptr<input_t> &input, std::vector<std::uint8_t> &&input_data);

#ifdef PLANK_TRANSPORT
  /**
   * @brief Validate and inject one native KyProto input message.
   *
   * @return true when the typed PLANK message was accepted.
   */
  bool native(std::shared_ptr<input_t> &input, std::uint8_t type,
              const std::uint8_t *payload, std::size_t payload_size);
#endif

  /**
   * @brief Initialize global input resources and platform backends.
   *
   * Retained tablet endpoints live until this subsystem shuts down, independently
   * of stream reservations. Reset releases held input without deleting devices.
   *
   * @return Cleanup handle for initialized input resources, or null if none are required.
   */
  [[nodiscard]] std::unique_ptr<platf::deinit_t> init();

  /**
   * @brief Allocate and initialize platform input state for a stream.
   *
   * @param mail Mailbox used to exchange messages with worker threads.
   * @param session_id Internal desktop identity shared by launch and resume connections.
   * @param connection_id Receives the lease identifying this stream binding.
   * @return Shared input state bound to the stream mailbox.
   */
  std::shared_ptr<input_t> alloc(safe::mail_t mail, std::string session_id, std::uint64_t &connection_id);

#ifdef SUNSHINE_TESTS
  namespace testing {
    /**
     * @brief Replace the global platform input backend for a unit test.
     *
     * @param input Test-owned platform input backend.
     */
    void set_platform_input(platf::input_t input);

    /**
     * @brief Process a raw HID frame directly for lifecycle tests.
     */
    bool handle_raw_hid(const std::shared_ptr<input_t> &input, const std::vector<std::uint8_t> &frame);

    /**
     * @brief Return the raw HID generation retained by a test input session.
     */
    std::uint16_t raw_hid_generation(const std::shared_ptr<input_t> &input);

    /** @brief Access a retained tablet while no input receiver is running. */
    raw_hid::tablet_t &raw_tablet(const std::shared_ptr<input_t> &input);

    /**
     * @brief Return whether a test session currently exposes normalized pen fallback.
     */
    bool normalized_pen_enabled(const std::shared_ptr<input_t> &input);

    /**
     * @brief Select normalized pen ownership directly for lifecycle tests.
     */
    void select_normalized_pen(const std::shared_ptr<input_t> &input);

    /**
     * @brief Submit one keyboard transition directly for policy tests.
     */
    void handle_keyboard(const std::shared_ptr<input_t> &input, std::uint16_t key_code, bool release);

    /**
     * @brief Submit one mouse-button transition directly for lifecycle tests.
     *
     * @param input Retained test input session.
     * @param button Moonlight button identifier.
     * @param release True for button release, false for button press.
     */
    void handle_mouse_button(const std::shared_ptr<input_t> &input, std::uint8_t button, bool release);

    /**
     * @brief Return the last key submitted to the fake platform keyboard.
     */
    std::uint16_t last_keyboard_code();

    /** @brief Hold the production input barrier for a deterministic concurrency test. */
    void with_input_lock(const std::function<void()> &action);

    /** @brief Access the fake per-client backend while no input thread is running. */
    platf::client_input_t *client_context(const std::shared_ptr<input_t> &input);
  }  // namespace testing
#endif

  /**
   * @brief Touchscreen coordinate bounds used to scale absolute input.
   */
  struct touch_port_t: public platf::touch_port_t {
    int env_width;  ///< Width of the full capture environment in physical pixels.
    int env_height;  ///< Height of the full capture environment in physical pixels.

    // Offset x and y coordinates of the client
    float client_offsetX;  ///< Horizontal client viewport offset used when scaling touch input.
    float client_offsetY;  ///< Vertical client viewport offset used when scaling touch input.

    float scalar_inv;  ///< Inverse scale factor from client coordinates to display coordinates.
    float scalar_tpcoords;  ///< Scale factor from client coordinates to touch-port coordinates.

    int env_logical_width;  ///< Width of the full capture environment after display scaling.
    int env_logical_height;  ///< Height of the full capture environment after display scaling.

    /**
     * @brief Check whether the touch-port bounds are initialized.
     */
    explicit operator bool() const {
      return width != 0 && height != 0 && env_width != 0 && env_height != 0;
    }
  };

  /**
   * @brief Scale the ellipse axes according to the provided size.
   * @param val The major and minor axis pair.
   * @param rotation The rotation value from the pen event.
   * @param scalar The scalar cartesian coordinate pair.
   * @return The major and minor axis pair.
   */
  std::pair<float, float> scale_client_contact_area(const std::pair<float, float> &val, uint16_t rotation, const std::pair<float, float> &scalar);
}  // namespace input
