/**
 * @file src/input.cpp
 * @brief Definitions for keyboard, mouse, pen, and raw-HID input handling.
 */
#include <cstdint>
extern "C" {
#include <moonlight-common-c/src/Input.h>
#include <moonlight-common-c/src/Limelight.h>
}

// standard includes
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

// lib includes
#include <boost/endian/buffers.hpp>

// platform includes
#ifdef SUNSHINE_BUILD_X11
  #include <X11/XKBlib.h>
  #include <X11/keysym.h>
#endif

// local includes
#include "config.h"
#include "globals.h"
#include "input.h"
#include "raw_hid_tablet.h"
#include "logging.h"
#include "platform/common.h"
#include "platform/virtualhid_input.h"
#include "thread_pool.h"
#include "utility.h"

#ifdef PLANK_TRANSPORT
  #include <plank_transport_input.h>
#endif

// Win32 WHEEL_DELTA constant
#ifndef WHEEL_DELTA
constexpr int WHEEL_DELTA = 120;  ///< Standard Windows wheel delta used to normalize scroll events.
#endif

using namespace std::literals;

namespace input {

  constexpr auto VKEY_SHIFT = 0x10;  ///< Windows virtual-key code for shift.
  constexpr auto VKEY_LSHIFT = 0xA0;  ///< Windows virtual-key code for lshift.
  constexpr auto VKEY_RSHIFT = 0xA1;  ///< Windows virtual-key code for rshift.
  constexpr auto VKEY_CONTROL = 0x11;  ///< Windows virtual-key code for control.
  constexpr auto VKEY_LCONTROL = 0xA2;  ///< Windows virtual-key code for lcontrol.
  constexpr auto VKEY_RCONTROL = 0xA3;  ///< Windows virtual-key code for rcontrol.
  constexpr auto VKEY_MENU = 0x12;  ///< Windows virtual-key code for menu.
  constexpr auto VKEY_LMENU = 0xA4;  ///< Windows virtual-key code for lmenu.
  constexpr auto VKEY_RMENU = 0xA5;  ///< Windows virtual-key code for rmenu.
  constexpr auto VKEY_NUMLOCK = 0x90;  ///< Windows virtual-key code for Num Lock.

  /**
   * @brief Force the active X11 desktop's Num Lock modifier on.
   *
   * PLANK is a workstation product and always treats the numeric
   * keypad as numeric input. Querying the live XKB modifier avoids blindly
   * toggling a host state that can persist across stream connections.
   *
   * @return True when Num Lock is confirmed enabled.
   */
  bool enable_num_lock() {
#ifdef SUNSHINE_BUILD_X11
    auto *display = XOpenDisplay(nullptr);
    if (!display) {
      return false;
    }

    const auto num_lock_mask = XkbKeysymToModifiers(display, XK_Num_Lock);
    XkbStateRec state {};
    auto enabled = num_lock_mask != 0 &&
                   XkbGetState(display, XkbUseCoreKbd, &state) == Success &&
                   (state.locked_mods & num_lock_mask) == num_lock_mask;
    if (!enabled && num_lock_mask != 0 &&
        XkbLockModifiers(display, XkbUseCoreKbd, num_lock_mask, num_lock_mask)) {
      XSync(display, False);
      enabled = XkbGetState(display, XkbUseCoreKbd, &state) == Success &&
                (state.locked_mods & num_lock_mask) == num_lock_mask;
    }

    XCloseDisplay(display);
    return enabled;
#else
    return false;
#endif
  }

  /**
   * @brief Return whether a virtual key depends on the numeric keypad mode.
   */
  bool is_numeric_keypad_key(const std::uint16_t key_code) {
    return (key_code >= 0x60 && key_code <= 0x69) || key_code == 0x6E;
  }

  /**
   * @brief Packed identifier for a pressed key and its modifier flags.
   */
  typedef uint32_t key_press_id_t;

  /**
   * @brief Create a key-press identifier from the virtual-key code and flags.
   *
   * @param vk Virtual-key code from the client input packet.
   * @param flags Bit flags that modify the requested operation.
   * @return Constructed kpid object.
   */
  key_press_id_t make_kpid(uint16_t vk, uint8_t flags) {
    return (key_press_id_t) vk << 8 | flags;
  }

  /**
   * @brief Extract the virtual-key code from a packed key-press identifier.
   *
   * @param kpid Key-press identifier containing the virtual-key code and flags.
   * @return Virtual-key code stored in the high byte.
   */
  uint16_t vk_from_kpid(key_press_id_t kpid) {
    return kpid >> 8;
  }

  /**
   * @brief Extract the modifier flags from a packed key-press identifier.
   *
   * @param kpid Key-press identifier containing the virtual-key code and flags.
   * @return Modifier flags stored in the low byte.
   */
  uint8_t flags_from_kpid(key_press_id_t kpid) {
    return kpid & 0xFF;
  }

  /**
   * @brief Convert a little-endian netfloat to a native endianness float.
   * @param f Little-endian network float bytes.
   * @return Floating-point value decoded for the host CPU.
   */
  float from_netfloat(netfloat f) {
    return boost::endian::endian_load<float, sizeof(float), boost::endian::order::little>(f);
  }

  void to_netfloat(float value, netfloat output) {
    boost::endian::endian_store<float, sizeof(float), boost::endian::order::little>(output, value);
  }

  /**
   * @brief Convert a little-endian netfloat to a native float and clamp it to a range.
   * @param f Little-endian network float bytes.
   * @param min The minimium value for clamping.
   * @param max The maximum value for clamping.
   * @return Decoded floating-point value clamped between min and max.
   */
  float from_clamped_netfloat(netfloat f, float min, float max) {
    return std::clamp(from_netfloat(f), min, max);
  }

  static task_pool_util::TaskPool::task_id_t key_press_repeat_id {};
  // Native delivery no longer runs on task_pool. Serialize delivery, timers,
  // lease changes and cleanup explicitly; a generation check alone is not a
  // barrier against a new connection attaching while cleanup is in progress.
  static std::mutex input_state_mutex;
  static std::unordered_map<key_press_id_t, bool> key_press {};
  static std::array<std::uint8_t, 5> mouse_press {};

  static platf::input_t platf_input;
  /**
   * @brief Input emulation settings loaded from configuration.
   */
  struct input_t {
    /**
     * @brief Enumerates supported shortkey options.
     */
    enum shortkey_e {
      CTRL = 0x1,  ///< Control key
      ALT = 0x2,  ///< Alt key
      SHIFT = 0x4,  ///< Shift key
      SHORTCUT = CTRL | ALT | SHIFT  ///< Shortcut combination
    };

    /**
     * @brief Construct input state from the mailbox and platform backend.
     *
     * @param touch_port_event Event carrying the active touch port.
     * @param raw_hid_feedback_queue Queue used for raw tablet control requests.
     */
    input_t(
      safe::mail_raw_t::event_t<input::touch_port_t> touch_port_event,
      raw_hid::feedback_queue_t raw_hid_feedback_queue
    ):
        shortcutFlags {},
        client_context {platf::allocate_client_input_context(platf_input)},
        touch_port_event {std::move(touch_port_event)},
        raw_hid_tablet {std::make_unique<raw_hid::tablet_t>(std::move(raw_hid_feedback_queue))},
        raw_hid_owns_tablet {false},
        connection_id {0},
        touch_port {{0, 0, 0, 0}, 0, 0, 1.0f, 1.0f, 0, 0},
        accumulated_vscroll_delta {},
        accumulated_hscroll_delta {} {
    }

    // Keep track of alt+ctrl+shift key combo
    int shortcutFlags;  ///< Shortcut flags.

    bool left_alt_pressed = false;  ///< Tracks whether the left Alt key is currently pressed.
    bool right_alt_pressed = false;  ///< Tracks whether the right Alt key is currently pressed.

    std::unique_ptr<platf::client_input_t> client_context;  ///< Client context.

    safe::mail_raw_t::event_t<input::touch_port_t> touch_port_event;  ///< Touch port event.
    std::unique_ptr<raw_hid::tablet_t> raw_hid_tablet;  ///< Exact client tablet retained for this desktop worker.
    bool raw_hid_owns_tablet;  ///< Whether exact UHID endpoints suppress the normalized pen fallback.
    std::atomic<std::uint64_t> connection_id;  ///< Most recent stream lease bound to this retained state.

    std::list<std::vector<uint8_t>> input_queue;  ///< Pending raw input packets waiting for processing.
    std::mutex input_queue_lock;  ///< Input queue lock.

    input::touch_port_t touch_port;  ///< Touch coordinate bounds for the current stream.

    int32_t accumulated_vscroll_delta;  ///< Accumulated vscroll delta.
    int32_t accumulated_hscroll_delta;  ///< Accumulated hscroll delta.
  };

  /**
   * @brief Hash string-like session identifiers without allocating temporary strings.
   */
  struct transparent_string_hash_t {
    using is_transparent = void;  ///< Enable heterogeneous unordered-map lookup.

    /**
     * @brief Hash a string view.
     *
     * @param value Session identifier to hash.
     * @return Hash value for the supplied identifier.
     */
    std::size_t operator()(const std::string_view value) const noexcept {
      return std::hash<std::string_view> {}(value);
    }
  };

  using retained_input_map_t = std::unordered_map<
    std::string,
    std::shared_ptr<input_t>,
    transparent_string_hash_t,
    std::equal_to<>>;  ///< Retained inputs keyed by the internal desktop identity.

  /**
   * @brief Synchronized storage for retained input sessions.
   */
  struct retained_input_state_t {
    std::mutex mutex;  ///< Synchronizes retained session access across transport threads.
    retained_input_map_t inputs;  ///< Desktop input devices, independent of stream reservation lifetime.
  };

  /**
   * @brief Access process-wide retained input session storage.
   *
   * @return Mutable retained input session state.
   */
  retained_input_state_t &retained_input_state() {
    static retained_input_state_t state;
    return state;
  }

  /**
   * @brief Keep exact raw-HID and normalized tablet backends mutually exclusive.
   *
   * Flame applies its Tablet Margin controls to one XInput tablet. Leaving the
   * normalized fallback present beside an exact raw Wacom device can make
   * Flame configure the inactive fallback while pressure arrives from the raw
   * device. Suspended raw endpoints still own tablet identity and therefore
   * continue to suppress the fallback.
   *
   * @param input Retained per-client input state.
   */
  void sync_tablet_backend(const std::shared_ptr<input_t> &input) {
    const bool raw_hid_owns_tablet = input->raw_hid_tablet->has_endpoints();
    if (raw_hid_owns_tablet == input->raw_hid_owns_tablet) {
      return;
    }

    platf::set_normalized_pen_enabled(input->client_context.get(), !raw_hid_owns_tablet);
    input->raw_hid_owns_tablet = raw_hid_owns_tablet;
    if (raw_hid_owns_tablet) {
      BOOST_LOG(info) << "Exact raw HID tablet active; removed normalized pen fallback"sv;
    } else {
      BOOST_LOG(info) << "Exact raw HID tablet detached; restored normalized pen fallback"sv;
    }
  }

  /**
   * @brief Make a normalized pen packet authoritative for tablet ownership.
   *
   * A client may reconnect with a first-generation Intuos Pro after a newer
   * Wacom session left resumable UHID endpoints on the host. The normalized
   * client deliberately sends no raw-HID attachment, so its first pen packet
   * is the explicit transport transition that releases those stale endpoints
   * and restores the generic pen before the packet is delivered.
   */
  void select_normalized_pen_backend(const std::shared_ptr<input_t> &input) {
    if (!input->raw_hid_tablet->has_endpoints()) {
      return;
    }

    input->raw_hid_tablet->reset();
    sync_tablet_backend(input);
    BOOST_LOG(info) << "Normalized pen transport selected; released retained exact raw HID tablet endpoints"sv;
  }

  /**
   * @brief Process one raw-HID frame and synchronize tablet backend ownership.
   */
  bool handle_raw_hid_frame(const std::shared_ptr<input_t> &input, const std::vector<std::uint8_t> &frame) {
    const bool accepted = input->raw_hid_tablet->handle(frame);
    sync_tablet_backend(input);
    return accepted;
  }

  /**
   * @brief Rebind retained input state to a resumed stream mailbox.
   *
   * @param input Retained input state.
   * @param mail Mailbox for the resumed stream connection.
   */
  void rebind_input(const std::shared_ptr<input_t> &input, const safe::mail_t &mail) {
    input->touch_port_event = mail->event<input::touch_port_t>(mail::touch_port);
    input->raw_hid_tablet->rebind(mail->queue<std::vector<std::uint8_t>>(mail::raw_hid_feedback));
  }

  /**
   * @brief Apply shortcut based on VKEY
   * @param keyCode The VKEY code
   * @return 0 if no shortcut applied, > 0 if shortcut applied.
   */
  inline int apply_shortcut(short keyCode) {
    constexpr auto VK_F1 = 0x70;
    constexpr auto VK_F13 = 0x7C;

    BOOST_LOG(debug) << "Apply Shortcut: 0x"sv << util::hex((std::uint8_t) keyCode).to_string_view();

    if (keyCode >= VK_F1 && keyCode <= VK_F13) {
      mail::man->event<int>(mail::switch_display)->raise(keyCode - VK_F1);
      return 1;
    }

    return 0;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PNV_REL_MOUSE_MOVE_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin relative mouse move packet--"sv << std::endl
      << "deltaX ["sv << util::endian::big(packet->deltaX) << ']' << std::endl
      << "deltaY ["sv << util::endian::big(packet->deltaY) << ']' << std::endl
      << "--end relative mouse move packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PNV_ABS_MOUSE_MOVE_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin absolute mouse move packet--"sv << std::endl
      << "x      ["sv << util::endian::big(packet->x) << ']' << std::endl
      << "y      ["sv << util::endian::big(packet->y) << ']' << std::endl
      << "width  ["sv << util::endian::big(packet->width) << ']' << std::endl
      << "height ["sv << util::endian::big(packet->height) << ']' << std::endl
      << "--end absolute mouse move packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PNV_MOUSE_BUTTON_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin mouse button packet--"sv << std::endl
      << "action ["sv << util::hex(packet->header.magic).to_string_view() << ']' << std::endl
      << "button ["sv << util::hex(packet->button).to_string_view() << ']' << std::endl
      << "--end mouse button packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PNV_SCROLL_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin mouse scroll packet--"sv << std::endl
      << "scrollAmt1 ["sv << util::endian::big(packet->scrollAmt1) << ']' << std::endl
      << "--end mouse scroll packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PSS_HSCROLL_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin mouse hscroll packet--"sv << std::endl
      << "scrollAmount ["sv << util::endian::big(packet->scrollAmount) << ']' << std::endl
      << "--end mouse hscroll packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PNV_KEYBOARD_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin keyboard packet--"sv << std::endl
      << "keyAction ["sv << util::hex(packet->header.magic).to_string_view() << ']' << std::endl
      << "keyCode ["sv << util::hex(packet->keyCode).to_string_view() << ']' << std::endl
      << "modifiers ["sv << util::hex(packet->modifiers).to_string_view() << ']' << std::endl
      << "flags ["sv << util::hex(packet->flags).to_string_view() << ']' << std::endl
      << "--end keyboard packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PNV_UNICODE_PACKET packet) {
    std::string text(packet->text, util::endian::big(packet->header.size) - sizeof(packet->header.magic));
    BOOST_LOG(debug)
      << "--begin unicode packet--"sv << std::endl
      << "text ["sv << text << ']' << std::endl
      << "--end unicode packet--"sv;
  }

  /**
   * @brief Prints a pen packet.
   * @param packet The pen packet.
   */
  void print(PSS_PEN_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin pen packet--"sv << std::endl
      << "eventType ["sv << util::hex(packet->eventType).to_string_view() << ']' << std::endl
      << "toolType ["sv << util::hex(packet->toolType).to_string_view() << ']' << std::endl
      << "penButtons ["sv << util::hex(packet->penButtons).to_string_view() << ']' << std::endl
      << "x ["sv << from_netfloat(packet->x) << ']' << std::endl
      << "y ["sv << from_netfloat(packet->y) << ']' << std::endl
      << "pressureOrDistance ["sv << from_netfloat(packet->pressureOrDistance) << ']' << std::endl
      << "contactAreaMajor ["sv << from_netfloat(packet->contactAreaMajor) << ']' << std::endl
      << "contactAreaMinor ["sv << from_netfloat(packet->contactAreaMinor) << ']' << std::endl
      << "rotation ["sv << (uint32_t) packet->rotation << ']' << std::endl
      << "tilt ["sv << (uint32_t) packet->tilt << ']' << std::endl
      << "--end pen packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   */
  void print(void *payload) {
    auto header = (PNV_INPUT_HEADER) payload;

    switch (util::endian::little(header->magic)) {
      case MOUSE_MOVE_REL_MAGIC_GEN5:
        print((PNV_REL_MOUSE_MOVE_PACKET) payload);
        break;
      case MOUSE_MOVE_ABS_MAGIC:
        print((PNV_ABS_MOUSE_MOVE_PACKET) payload);
        break;
      case MOUSE_BUTTON_DOWN_EVENT_MAGIC_GEN5:
      case MOUSE_BUTTON_UP_EVENT_MAGIC_GEN5:
        print((PNV_MOUSE_BUTTON_PACKET) payload);
        break;
      case SCROLL_MAGIC_GEN5:
        print((PNV_SCROLL_PACKET) payload);
        break;
      case SS_HSCROLL_MAGIC:
        print((PSS_HSCROLL_PACKET) payload);
        break;
      case KEY_DOWN_EVENT_MAGIC:
      case KEY_UP_EVENT_MAGIC:
        print((PNV_KEYBOARD_PACKET) payload);
        break;
      case UTF8_TEXT_EVENT_MAGIC:
        print((PNV_UNICODE_PACKET) payload);
        break;
      case SS_PEN_MAGIC:
        print((PSS_PEN_PACKET) payload);
        break;
      case SS_RAW_HID_MAGIC:
        BOOST_LOG(verbose) << "Raw HID tablet frame"sv;
        break;
    }
  }

  /**
   * @brief Forward a client input packet directly to the platform backend.
   *
   * @param input Platform input backend that receives the event.
   * @param packet Protocol packet being processed.
   */
  void passthrough(std::shared_ptr<input_t> &input, PNV_REL_MOUSE_MOVE_PACKET packet) {
    if (!config::input.mouse) {
      return;
    }

    platf::move_mouse(platf_input, util::endian::big(packet->deltaX), util::endian::big(packet->deltaY));
  }

  /**
   * @brief Converts client coordinates on the specified surface into screen coordinates.
   * @param input The input context.
   * @param val The cartesian coordinate pair to convert.
   * @param size The size of the client's surface containing the value.
   * @return The host-relative coordinate pair if a touchport is available.
   */
  std::optional<std::pair<float, float>> client_to_touchport(std::shared_ptr<input_t> &input, const std::pair<float, float> &val, const std::pair<float, float> &size) {
    auto &touch_port_event = input->touch_port_event;
    auto &touch_port = input->touch_port;
    if (touch_port_event->peek()) {
      touch_port = *touch_port_event->pop();
    }
    if (!touch_port) {
      BOOST_LOG(verbose) << "Ignoring early absolute input without a touch port"sv;
      return std::nullopt;
    }

    auto scalarX = touch_port.width / size.first;
    auto scalarY = touch_port.height / size.second;

    float x = std::clamp(val.first, 0.0f, size.first) * scalarX;
    float y = std::clamp(val.second, 0.0f, size.second) * scalarY;

    auto offsetX = touch_port.client_offsetX;
    auto offsetY = touch_port.client_offsetY;

    x = std::clamp(x, offsetX, (size.first * scalarX) - offsetX);
    y = std::clamp(y, offsetY, (size.second * scalarY) - offsetY);

    /*
    x and y here below have the coordinates of the surface of the streaming resolution,
    and are dependent on how that comes configured from the client (scalar_inv is calculated
    from the proportion of that and the device's **physical** size).
    */
    x = (x - offsetX) * touch_port.scalar_inv;
    y = (y - offsetY) * touch_port.scalar_inv;

    /*
    This final operation is a bit weird and has been brought about with lots of trial and error. A better
    way to do this may exist.

    Basically, this is what makes the touchscreen map to the logical virtual input coordinates properly.
    Since the virtual input dimensions are logical (because scaling breaks everything otherwise), using the previous
    x and y coordinates would be incorrect when screens are scaled, because the touch port is smaller (or larger)
    by a factor (that factor is touch_port.scalar_tpcoords), and that factor must be used to account for that difference
    when moving the cursor. Otherwise, it will move either slower or faster than your finger proportionally to
    scalar_tpcoords, and be offset *inversely* proportionally to scalar_tpcoords. So you must account for both differences
    by multiplying and dividing.
    */
    float final_x = (x + touch_port.offset_x * touch_port.scalar_tpcoords) / touch_port.scalar_tpcoords;
    float final_y = (y + touch_port.offset_y * touch_port.scalar_tpcoords) / touch_port.scalar_tpcoords;
    return std::pair {final_x, final_y};
  }

  /**
   * @brief Multiply a polar coordinate pair by a cartesian scaling factor.
   * @param r The radial coordinate.
   * @param angle The angular coordinate (radians).
   * @param scalar The scalar cartesian coordinate pair.
   * @return The scaled radial coordinate.
   */
  float multiply_polar_by_cartesian_scalar(float r, float angle, const std::pair<float, float> &scalar) {
    // Convert polar to cartesian coordinates
    float x = r * std::cos(angle);
    float y = r * std::sin(angle);

    // Scale the values
    x *= scalar.first;
    y *= scalar.second;

    // Convert the result back to a polar radial coordinate
    return std::sqrt(std::pow(x, 2) + std::pow(y, 2));
  }

  std::pair<float, float> scale_client_contact_area(const std::pair<float, float> &val, uint16_t rotation, const std::pair<float, float> &scalar) {
    // If the rotation is unknown, we'll just scale both axes equally by using
    // a 45-degree angle for our scaling calculations
    float angle = rotation == LI_ROT_UNKNOWN ? (M_PI / 4) : (rotation * (M_PI / 180));

    // If we have a major but not a minor axis, treat the touch as circular
    float major = val.first;
    float minor = val.second != 0.0f ? val.second : val.first;

    // The minor axis is perpendicular to major axis so the angle must be rotated by 90 degrees
    return {multiply_polar_by_cartesian_scalar(major, angle, scalar), multiply_polar_by_cartesian_scalar(minor, angle + (M_PI / 2), scalar)};
  }

  /**
   * @brief Forward a client input packet directly to the platform backend.
   *
   * @param input Platform input backend that receives the event.
   * @param packet Protocol packet being processed.
   */
  void passthrough(std::shared_ptr<input_t> &input, PNV_ABS_MOUSE_MOVE_PACKET packet) {
    if (!config::input.mouse) {
      return;
    }

    float x = util::endian::big(packet->x);
    float y = util::endian::big(packet->y);

    // Prevent divide by zero
    // Don't expect it to happen, but just in case
    if (!packet->width || !packet->height) {
      BOOST_LOG(warning) << "PLANK Client passed invalid dimensions"sv;

      return;
    }

    auto width = (float) util::endian::big(packet->width);
    auto height = (float) util::endian::big(packet->height);

    auto tpcoords = client_to_touchport(input, {x, y}, {width, height});
    if (!tpcoords) {
      return;
    }

    auto &touch_port = input->touch_port;

    int touch_port_dim_x;
    int touch_port_dim_y;
    if (touch_port.env_logical_width != 0 && touch_port.env_logical_height != 0) {
      touch_port_dim_x = touch_port.env_logical_width;
      touch_port_dim_y = touch_port.env_logical_height;
    } else {
      touch_port_dim_x = touch_port.env_width;
      touch_port_dim_y = touch_port.env_height;
    }

    platf::touch_port_t abs_port {
      touch_port.offset_x,
      touch_port.offset_y,
      touch_port_dim_x,
      touch_port_dim_y
    };

    platf::abs_mouse(platf_input, abs_port, tpcoords->first, tpcoords->second);
  }

  /**
   * @brief Called to pass a mouse button message to the platform backend.
   *
   * @param input The input context pointer.
   * @param packet The mouse button packet.
   */
  void passthrough(std::shared_ptr<input_t> &input, PNV_MOUSE_BUTTON_PACKET packet) {
    if (!config::input.mouse) {
      return;
    }

    auto release = util::endian::little(packet->header.magic) == MOUSE_BUTTON_UP_EVENT_MAGIC_GEN5;
    auto button = util::endian::big(packet->button);
    if (button > 0 && button < mouse_press.size()) {
      if (mouse_press[button] != release) {
        // button state is already what we want
        return;
      }

      mouse_press[button] = !release;
    }
    // PLANK sends explicit button transitions. Preserve their order without
    // delaying left releases or synthesizing right clicks between transitions.
    platf::button_mouse(platf_input, button, release);
  }

  /**
   * @brief Apply configured keybinding remaps to a platform keycode.
   *
   * @param keycode Platform keycode being translated or emitted.
   * @return Remapped keycode when configured, otherwise the original keycode.
   */
  short map_keycode(short keycode) {
    auto it = config::input.keybindings.find(keycode);
    if (it != std::end(config::input.keybindings)) {
      return it->second;
    }

    return keycode;
  }

  /**
   * @brief Update flags for keyboard shortcut combo's
   *
   * @param flags Bit flags that modify the requested operation.
   * @param keyCode Moonlight keyboard packet key code.
   * @param release Whether the key or button event is a release.
   */
  inline void update_shortcutFlags(int *flags, short keyCode, bool release) {
    switch (keyCode) {
      case VKEY_SHIFT:
      case VKEY_LSHIFT:
      case VKEY_RSHIFT:
        if (release) {
          *flags &= ~input_t::SHIFT;
        } else {
          *flags |= input_t::SHIFT;
        }
        break;
      case VKEY_CONTROL:
      case VKEY_LCONTROL:
      case VKEY_RCONTROL:
        if (release) {
          *flags &= ~input_t::CTRL;
        } else {
          *flags |= input_t::CTRL;
        }
        break;
      case VKEY_MENU:
      case VKEY_LMENU:
      case VKEY_RMENU:
        if (release) {
          *flags &= ~input_t::ALT;
        } else {
          *flags |= input_t::ALT;
        }
        break;
    }
  }

  /**
   * @brief Check whether modifier.
   *
   * @param keyCode Moonlight keyboard packet key code.
   * @return True when the key code is a keyboard modifier.
   */
  bool is_modifier(uint16_t keyCode) {
    switch (keyCode) {
      case VKEY_SHIFT:
      case VKEY_LSHIFT:
      case VKEY_RSHIFT:
      case VKEY_CONTROL:
      case VKEY_LCONTROL:
      case VKEY_RCONTROL:
      case VKEY_MENU:
      case VKEY_LMENU:
      case VKEY_RMENU:
        return true;
      default:
        return false;
    }
  }

  /**
   * @brief Send key and modifiers.
   *
   * @param key_code Moonlight keyboard packet key code.
   * @param release Whether the key or button event is a release.
   * @param flags Bit flags that modify the requested operation.
   * @param synthetic_modifiers Synthetic modifiers.
   */
  void send_key_and_modifiers(uint16_t key_code, bool release, uint8_t flags, uint8_t synthetic_modifiers) {
    if (!release) {
      // Press any synthetic modifiers required for this key
      if (synthetic_modifiers & MODIFIER_SHIFT) {
        platf::keyboard_update(platf_input, VKEY_SHIFT, false, flags);
      }
      if (synthetic_modifiers & MODIFIER_CTRL) {
        platf::keyboard_update(platf_input, VKEY_CONTROL, false, flags);
      }
      if (synthetic_modifiers & MODIFIER_ALT) {
        platf::keyboard_update(platf_input, VKEY_MENU, false, flags);
      }
    }

    platf::keyboard_update(platf_input, map_keycode(key_code), release, flags);

    if (!release) {
      // Raise any synthetic modifier keys we pressed
      if (synthetic_modifiers & MODIFIER_SHIFT) {
        platf::keyboard_update(platf_input, VKEY_SHIFT, true, flags);
      }
      if (synthetic_modifiers & MODIFIER_CTRL) {
        platf::keyboard_update(platf_input, VKEY_CONTROL, true, flags);
      }
      if (synthetic_modifiers & MODIFIER_ALT) {
        platf::keyboard_update(platf_input, VKEY_MENU, true, flags);
      }
    }
  }

  /**
   * @brief Re-emit a held key until its repeat task is cancelled.
   *
   * @param key_code Moonlight keyboard packet key code.
   * @param flags Bit flags that modify the requested operation.
   * @param synthetic_modifiers Synthetic modifiers.
   */
  void repeat_key(uint16_t key_code, uint8_t flags, uint8_t synthetic_modifiers) {
    std::lock_guard lock {input_state_mutex};
    // If key no longer pressed, stop repeating
    if (!key_press[make_kpid(key_code, flags)]) {
      key_press_repeat_id = nullptr;
      return;
    }

    send_key_and_modifiers(key_code, false, flags, synthetic_modifiers);

    key_press_repeat_id = task_pool.pushDelayed(repeat_key, config::input.key_repeat_period, key_code, flags, synthetic_modifiers).task_id;
  }

  /**
   * @brief Forward a client input packet directly to the platform backend.
   *
   * @param input Platform input backend that receives the event.
   * @param packet Protocol packet being processed.
   */
  void passthrough(std::shared_ptr<input_t> &input, PNV_KEYBOARD_PACKET packet) {
    if (!config::input.keyboard) {
      return;
    }

    auto release = util::endian::little(packet->header.magic) == KEY_UP_EVENT_MAGIC;
    auto keyCode = packet->keyCode & 0x00FF;

    // Num Lock is an always-on PLANK invariant. Consume the client's
    // lock-key transition so differing local LED state cannot invert the host,
    // and reassert the host state before any keypad key that depends on it.
    if (keyCode == VKEY_NUMLOCK) {
      if (!release && !enable_num_lock()) {
        BOOST_LOG(debug) << "Unable to confirm the always-on Num Lock policy"sv;
      }
      return;
    }
    if (!release && is_numeric_keypad_key(keyCode) && !enable_num_lock()) {
      BOOST_LOG(debug) << "Unable to confirm Num Lock before numeric keypad input"sv;
    }

    if (keyCode == VKEY_LMENU) {
      input->left_alt_pressed = !release;
    } else if (keyCode == VKEY_RMENU) {
      input->right_alt_pressed = !release;
    }

    // Right-alt maps to meta, so it must not also register as ALT
    int modifiers = packet->modifiers;
    if (config::input.key_rightalt_to_key_win && input->right_alt_pressed && !input->left_alt_pressed) {
      modifiers &= ~MODIFIER_ALT;
    }

    // Set synthetic modifier flags if the keyboard packet is requesting modifier
    // keys that are not current pressed.
    uint8_t synthetic_modifiers = 0;
    if (!release && !is_modifier(keyCode)) {
      if (!(input->shortcutFlags & input_t::SHIFT) && (modifiers & MODIFIER_SHIFT)) {
        synthetic_modifiers |= MODIFIER_SHIFT;
      }
      if (!(input->shortcutFlags & input_t::CTRL) && (modifiers & MODIFIER_CTRL)) {
        synthetic_modifiers |= MODIFIER_CTRL;
      }
      if (!(input->shortcutFlags & input_t::ALT) && (modifiers & MODIFIER_ALT)) {
        synthetic_modifiers |= MODIFIER_ALT;
      }
    }

    auto &pressed = key_press[make_kpid(keyCode, packet->flags)];
    if (!pressed) {
      if (!release) {
        // A new key has been pressed down, we need to check for key combo's
        // If a key-combo has been pressed down, don't pass it through
        if (input->shortcutFlags == input_t::SHORTCUT && apply_shortcut(keyCode) > 0) {
          return;
        }

        if (key_press_repeat_id) {
          task_pool.cancel(key_press_repeat_id);
        }

        if (config::input.key_repeat_delay.count() > 0) {
          key_press_repeat_id = task_pool.pushDelayed(repeat_key, config::input.key_repeat_delay, keyCode, packet->flags, synthetic_modifiers).task_id;
        }
      } else {
        // Already released
        return;
      }
    } else if (!release) {
      // Already pressed down key
      return;
    }

    pressed = !release;

    send_key_and_modifiers(keyCode, release, packet->flags, synthetic_modifiers);

    update_shortcutFlags(&input->shortcutFlags, map_keycode(keyCode), release);
  }

  /**
   * @brief Called to pass a vertical scroll message the platform backend.
   * @param input The input context pointer.
   * @param packet The scroll packet.
   */
  void passthrough(std::shared_ptr<input_t> &input, PNV_SCROLL_PACKET packet) {
    if (!config::input.mouse) {
      return;
    }

    if (config::input.high_resolution_scrolling) {
      platf::scroll(platf_input, util::endian::big(packet->scrollAmt1));
    } else {
      input->accumulated_vscroll_delta += util::endian::big(packet->scrollAmt1);
      auto full_ticks = input->accumulated_vscroll_delta / WHEEL_DELTA;
      if (full_ticks) {
        // Send any full ticks that have accumulated and store the rest
        platf::scroll(platf_input, full_ticks * WHEEL_DELTA);
        input->accumulated_vscroll_delta -= full_ticks * WHEEL_DELTA;
      }
    }
  }

  /**
   * @brief Called to pass a horizontal scroll message the platform backend.
   * @param input The input context pointer.
   * @param packet The scroll packet.
   */
  void passthrough(std::shared_ptr<input_t> &input, PSS_HSCROLL_PACKET packet) {
    if (!config::input.mouse) {
      return;
    }

    if (config::input.high_resolution_scrolling) {
      platf::hscroll(platf_input, util::endian::big(packet->scrollAmount));
    } else {
      input->accumulated_hscroll_delta += util::endian::big(packet->scrollAmount);
      auto full_ticks = input->accumulated_hscroll_delta / WHEEL_DELTA;
      if (full_ticks) {
        // Send any full ticks that have accumulated and store the rest
        platf::hscroll(platf_input, full_ticks * WHEEL_DELTA);
        input->accumulated_hscroll_delta -= full_ticks * WHEEL_DELTA;
      }
    }
  }

  /**
   * @brief Forward a client input packet directly to the platform backend.
   *
   * @param packet Protocol packet being processed.
   */
  void passthrough(const NV_UNICODE_PACKET *packet) {
    if (!config::input.keyboard) {
      return;
    }

    int size = util::endian::big(packet->header.size) - sizeof(packet->header.magic);
    platf::unicode(platf_input, packet->text, size);
  }

  /**
   * @brief Normalizes coordinates to monitor-local logical touch dimensions.
   * @param touch_port The current touch port metadata.
   * @param coords The in/out coordinate pair to normalize.
   * @return The monitor-local touch port, or std::nullopt if dimensions are invalid.
   */
  std::optional<platf::touch_port_t> monitor_touch_port(const input::touch_port_t &touch_port, std::pair<float, float> &coords) {
    const float monitor_logical_w = (touch_port.width * touch_port.scalar_inv) / touch_port.scalar_tpcoords;
    const float monitor_logical_h = (touch_port.height * touch_port.scalar_inv) / touch_port.scalar_tpcoords;
    if (monitor_logical_w <= 0.0f || monitor_logical_h <= 0.0f) {
      BOOST_LOG(warning) << "Ignoring pen input due to invalid logical pointer dimensions"sv;
      return std::nullopt;
    }

    coords.first = (coords.first - touch_port.offset_x) / monitor_logical_w;
    coords.second = (coords.second - touch_port.offset_y) / monitor_logical_h;

    return platf::touch_port_t {
      touch_port.offset_x,
      touch_port.offset_y,
      static_cast<int>(monitor_logical_w),
      static_cast<int>(monitor_logical_h)
    };
  }

  /**
   * @brief Shared normalized data prepared for a pen event.
   */
  struct absolute_pointer_data_t {
    platf::touch_port_t touch_port;  ///< Monitor-local touch port.
    std::pair<float, float> coords;  ///< Normalized monitor-local coordinates.
    std::uint16_t rotation;  ///< Normalized rotation in degrees.
    std::pair<float, float> contact_area;  ///< Scaled major and minor contact axes.
  };

  /**
   * @brief Normalize a pen packet into monitor-local coordinates.
   *
   * @tparam Packet Pointer type for a Moonlight pen packet.
   * @param input Input context that supplies the current pointer viewport metadata.
   * @param packet Pen packet to normalize.
   * @return Normalized pointer data, or `std::nullopt` when input is disabled or dimensions are invalid.
   */
  template<typename Packet>
  std::optional<absolute_pointer_data_t> prepare_absolute_pointer_data(std::shared_ptr<input_t> &input, Packet packet) {
    if (!config::input.mouse) {
      return std::nullopt;
    }

    auto coords = client_to_touchport(
      input,
      {from_clamped_netfloat(packet->x, 0.0f, 1.0f) * 65535.f, from_clamped_netfloat(packet->y, 0.0f, 1.0f) * 65535.f},
      {65535.f, 65535.f}
    );
    if (!coords) {
      return std::nullopt;
    }

    auto touch_port = monitor_touch_port(input->touch_port, *coords);
    if (!touch_port) {
      return std::nullopt;
    }

    auto rotation = util::endian::little(packet->rotation);
    if (rotation != LI_ROT_UNKNOWN) {
      rotation %= 360;
    }

    const auto contact_area = scale_client_contact_area(
      {from_clamped_netfloat(packet->contactAreaMajor, 0.0f, 1.0f) * 65535.f,
       from_clamped_netfloat(packet->contactAreaMinor, 0.0f, 1.0f) * 65535.f},
      rotation,
      {touch_port->width / 65535.f, touch_port->height / 65535.f}
    );

    return absolute_pointer_data_t {*touch_port, *coords, rotation, contact_area};
  }

  /**
   * @brief Called to pass a pen message to the platform backend.
   * @param input The input context pointer.
   * @param packet The pen packet.
   */
  void passthrough(std::shared_ptr<input_t> &input, PSS_PEN_PACKET packet) {
    if (packet->eventType == LI_TOUCH_EVENT_CANCEL_ALL || packet->eventType == LI_TOUCH_EVENT_CANCEL ||
        packet->eventType == LI_TOUCH_EVENT_HOVER_LEAVE) {
      // Releases must work even during a display transition without a viewport.
      platf::pen_input_t pen {};
      pen.eventType = packet->eventType;
      pen.toolType = LI_TOOL_TYPE_UNKNOWN;
      platf::pen_update(input->client_context.get(), {}, pen);
      return;
    }
    const auto pointer_data = prepare_absolute_pointer_data(input, packet);
    if (!pointer_data) {
      return;
    }

    platf::pen_input_t pen {
      packet->eventType,
      packet->toolType,
      packet->penButtons,
      packet->tilt,
      pointer_data->rotation,
      pointer_data->coords.first,
      pointer_data->coords.second,
      from_clamped_netfloat(packet->pressureOrDistance, 0.0f, 1.0f),
      pointer_data->contact_area.first,
      pointer_data->contact_area.second,
    };

    platf::pen_update(input->client_context.get(), pointer_data->touch_port, pen);
  }

  /**
   * @brief Enumerates supported batch result options.
   */
  enum class batch_result_e {
    batched,  ///< This entry was batched with the source entry
    not_batchable,  ///< Not eligible to batch but continue attempts to batch
    terminate_batch,  ///< Stop trying to batch with this entry
  };

  /**
   * @brief Batch two relative mouse messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PNV_REL_MOUSE_MOVE_PACKET dest, PNV_REL_MOUSE_MOVE_PACKET src) {
    short deltaX;
    short deltaY;

    // Batching is safe as long as the result doesn't overflow a 16-bit integer
    if (!__builtin_add_overflow(util::endian::big(dest->deltaX), util::endian::big(src->deltaX), &deltaX)) {
      return batch_result_e::terminate_batch;
    }
    if (!__builtin_add_overflow(util::endian::big(dest->deltaY), util::endian::big(src->deltaY), &deltaY)) {
      return batch_result_e::terminate_batch;
    }

    // Take the sum of deltas
    dest->deltaX = util::endian::big(deltaX);
    dest->deltaY = util::endian::big(deltaY);
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two absolute mouse messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PNV_ABS_MOUSE_MOVE_PACKET dest, PNV_ABS_MOUSE_MOVE_PACKET src) {
    // Batching must only happen if the reference width and height don't change
    if (dest->width != src->width || dest->height != src->height) {
      return batch_result_e::terminate_batch;
    }

    // Take the latest absolute position
    *dest = *src;
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two vertical scroll messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PNV_SCROLL_PACKET dest, PNV_SCROLL_PACKET src) {
    short scrollAmt;

    // Batching is safe as long as the result doesn't overflow a 16-bit integer
    if (!__builtin_add_overflow(util::endian::big(dest->scrollAmt1), util::endian::big(src->scrollAmt1), &scrollAmt)) {
      return batch_result_e::terminate_batch;
    }

    // Take the sum of delta
    dest->scrollAmt1 = util::endian::big(scrollAmt);
    dest->scrollAmt2 = util::endian::big(scrollAmt);
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two horizontal scroll messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PSS_HSCROLL_PACKET dest, PSS_HSCROLL_PACKET src) {
    short scrollAmt;

    // Batching is safe as long as the result doesn't overflow a 16-bit integer
    if (!__builtin_add_overflow(util::endian::big(dest->scrollAmount), util::endian::big(src->scrollAmount), &scrollAmt)) {
      return batch_result_e::terminate_batch;
    }

    // Take the sum of delta
    dest->scrollAmount = util::endian::big(scrollAmt);
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two pen messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PSS_PEN_PACKET dest, PSS_PEN_PACKET src) {
    // Only batch hover or move events
    if (dest->eventType != LI_TOUCH_EVENT_MOVE && dest->eventType != LI_TOUCH_EVENT_HOVER) {
      return batch_result_e::terminate_batch;
    }

    // Batched events must be the same type
    if (dest->eventType != src->eventType) {
      return batch_result_e::terminate_batch;
    }

    // Do not allow batching if the button state changes
    if (dest->penButtons != src->penButtons) {
      return batch_result_e::terminate_batch;
    }

    // Do not batch beyond tool changes
    if (dest->toolType != src->toolType) {
      return batch_result_e::terminate_batch;
    }

    // Take the latest state
    *dest = *src;
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two input messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PNV_INPUT_HEADER dest, PNV_INPUT_HEADER src) {
    // We can only batch if the packet types are the same
    if (dest->magic != src->magic) {
      return batch_result_e::terminate_batch;
    }

    // We can only batch certain message types
    switch (util::endian::little(dest->magic)) {
      case MOUSE_MOVE_REL_MAGIC_GEN5:
        return batch((PNV_REL_MOUSE_MOVE_PACKET) dest, (PNV_REL_MOUSE_MOVE_PACKET) src);
      case MOUSE_MOVE_ABS_MAGIC:
        return batch((PNV_ABS_MOUSE_MOVE_PACKET) dest, (PNV_ABS_MOUSE_MOVE_PACKET) src);
      case SCROLL_MAGIC_GEN5:
        return batch((PNV_SCROLL_PACKET) dest, (PNV_SCROLL_PACKET) src);
      case SS_HSCROLL_MAGIC:
        return batch((PSS_HSCROLL_PACKET) dest, (PSS_HSCROLL_PACKET) src);
      case SS_PEN_MAGIC:
        return batch((PSS_PEN_PACKET) dest, (PSS_PEN_PACKET) src);
      default:
        // Not a batchable message type
        return batch_result_e::terminate_batch;
    }
  }

  /**
   * @brief Called on a thread pool thread to process an input message.
   * @param input The input context pointer.
   */
  void passthrough_next_message(std::shared_ptr<input_t> input) {
    std::lock_guard state_lock {input_state_mutex};
    // 'entry' backs the 'payload' pointer, so they must remain in scope together
    std::vector<uint8_t> entry;
    PNV_INPUT_HEADER payload;

    // Lock the input queue while batching, but release it before sending
    // the input to the OS. This avoids potentially lengthy lock contention
    // in the control stream thread while input is being processed by the OS.
    {
      std::lock_guard<std::mutex> lg(input->input_queue_lock);

      // If all entries have already been processed, nothing to do
      if (input->input_queue.empty()) {
        return;
      }

      // Pop off the first entry, which we will send
      entry = input->input_queue.front();
      payload = (PNV_INPUT_HEADER) entry.data();
      input->input_queue.pop_front();

      // Try to batch with remaining items on the queue
      auto i = input->input_queue.begin();
      while (i != input->input_queue.end()) {
        auto batchable_entry = *i;
        auto batchable_payload = (PNV_INPUT_HEADER) batchable_entry.data();

        auto batch_result = batch(payload, batchable_payload);
        if (batch_result == batch_result_e::terminate_batch) {
          // Stop batching
          break;
        } else if (batch_result == batch_result_e::batched) {
          // Erase this entry since it was batched
          i = input->input_queue.erase(i);
        } else {
          // We couldn't batch this entry, but try to batch later entries.
          i++;
        }
      }
    }

    // Print the final input packet
    input::print((void *) payload);

    // Send the batched input to the OS
    switch (util::endian::little(payload->magic)) {
      case MOUSE_MOVE_REL_MAGIC_GEN5:
        passthrough(input, (PNV_REL_MOUSE_MOVE_PACKET) payload);
        break;
      case MOUSE_MOVE_ABS_MAGIC:
        passthrough(input, (PNV_ABS_MOUSE_MOVE_PACKET) payload);
        break;
      case MOUSE_BUTTON_DOWN_EVENT_MAGIC_GEN5:
      case MOUSE_BUTTON_UP_EVENT_MAGIC_GEN5:
        passthrough(input, (PNV_MOUSE_BUTTON_PACKET) payload);
        break;
      case SCROLL_MAGIC_GEN5:
        passthrough(input, (PNV_SCROLL_PACKET) payload);
        break;
      case SS_HSCROLL_MAGIC:
        passthrough(input, (PSS_HSCROLL_PACKET) payload);
        break;
      case KEY_DOWN_EVENT_MAGIC:
      case KEY_UP_EVENT_MAGIC:
        passthrough(input, (PNV_KEYBOARD_PACKET) payload);
        break;
      case UTF8_TEXT_EVENT_MAGIC:
        passthrough(static_cast<const NV_UNICODE_PACKET *>(static_cast<const void *>(payload)));
        break;
      case SS_PEN_MAGIC:
        select_normalized_pen_backend(input);
        passthrough(input, (PSS_PEN_PACKET) payload);
        break;
      case SS_RAW_HID_MAGIC: {
        const auto packet_size = static_cast<std::size_t>(util::endian::big(payload->size)) + sizeof(payload->size);
        if (packet_size >= sizeof(SS_RAW_HID_PACKET) - 1 && packet_size <= entry.size()) {
          const auto *packet = reinterpret_cast<const SS_RAW_HID_PACKET *>(payload);
          const auto frame_size = packet_size - (sizeof(SS_RAW_HID_PACKET) - 1);
          std::vector<std::uint8_t> frame(packet->data, packet->data + frame_size);
          if (!handle_raw_hid_frame(input, frame)) {
            BOOST_LOG(warning) << "Rejected malformed raw HID tablet frame"sv;
          }
        }
        break;
      }
    }
  }

  /**
   * @brief Called on the control stream thread to queue an input message.
   * @param input The input context pointer.
   * @param input_data The input message.
   */
  void passthrough(std::shared_ptr<input_t> &input, std::vector<std::uint8_t> &&input_data) {
    {
      std::lock_guard<std::mutex> lg(input->input_queue_lock);
      input->input_queue.push_back(std::move(input_data));
    }
    task_pool.push(passthrough_next_message, input);
  }

#ifdef PLANK_TRANSPORT
  bool native(std::shared_ptr<input_t> &input, std::uint8_t type,
              const std::uint8_t *payload, std::size_t payload_size) {
    std::lock_guard lock {input_state_mutex};
    if (!input || !payload || payload_size == 0) {
      return false;
    }

    switch (type) {
      case PLANK_TRANSPORT_INPUT_ABSOLUTE_MOUSE: {
        if (payload_size != PLANK_TRANSPORT_INPUT_ABSOLUTE_MOUSE_SIZE) {
          return false;
        }
        NV_ABS_MOUSE_MOVE_PACKET packet {};
        packet.header.magic = util::endian::little<std::uint32_t>(MOUSE_MOVE_ABS_MAGIC);
        packet.x = util::endian::big(plank_transport_input_read_u16(payload));
        packet.y = util::endian::big(plank_transport_input_read_u16(payload + 2));
        packet.width = util::endian::big(plank_transport_input_read_u16(payload + 4));
        packet.height = util::endian::big(plank_transport_input_read_u16(payload + 6));
        passthrough(input, &packet);
        return true;
      }
      case PLANK_TRANSPORT_INPUT_MOUSE_BUTTON: {
        if (payload_size != PLANK_TRANSPORT_INPUT_MOUSE_BUTTON_SIZE ||
            (payload[1] != PLANK_TRANSPORT_INPUT_ACTION_PRESS &&
             payload[1] != PLANK_TRANSPORT_INPUT_ACTION_RELEASE)) {
          return false;
        }
        NV_MOUSE_BUTTON_PACKET packet {};
        packet.header.magic = util::endian::little<std::uint32_t>(
          payload[1] == PLANK_TRANSPORT_INPUT_ACTION_PRESS ?
            MOUSE_BUTTON_DOWN_EVENT_MAGIC_GEN5 : MOUSE_BUTTON_UP_EVENT_MAGIC_GEN5
        );
        packet.button = payload[0];
        passthrough(input, &packet);
        return true;
      }
      case PLANK_TRANSPORT_INPUT_VERTICAL_SCROLL: {
        if (payload_size != PLANK_TRANSPORT_INPUT_SCROLL_SIZE) {
          return false;
        }
        NV_SCROLL_PACKET packet {};
        packet.scrollAmt1 = util::endian::big(
          static_cast<std::int16_t>(plank_transport_input_read_u16(payload))
        );
        passthrough(input, &packet);
        return true;
      }
      case PLANK_TRANSPORT_INPUT_HORIZONTAL_SCROLL: {
        if (payload_size != PLANK_TRANSPORT_INPUT_SCROLL_SIZE) {
          return false;
        }
        SS_HSCROLL_PACKET packet {};
        packet.scrollAmount = util::endian::big(
          static_cast<std::int16_t>(plank_transport_input_read_u16(payload))
        );
        passthrough(input, &packet);
        return true;
      }
      case PLANK_TRANSPORT_INPUT_KEYBOARD: {
        if (payload_size != PLANK_TRANSPORT_INPUT_KEYBOARD_SIZE ||
            (payload[2] != PLANK_TRANSPORT_INPUT_ACTION_PRESS &&
             payload[2] != PLANK_TRANSPORT_INPUT_ACTION_RELEASE)) {
          return false;
        }
        NV_KEYBOARD_PACKET packet {};
        packet.header.magic = util::endian::little<std::uint32_t>(
          payload[2] == PLANK_TRANSPORT_INPUT_ACTION_PRESS ?
            KEY_DOWN_EVENT_MAGIC : KEY_UP_EVENT_MAGIC
        );
        packet.keyCode = util::endian::little(
          static_cast<std::int16_t>(plank_transport_input_read_u16(payload))
        );
        packet.modifiers = static_cast<char>(payload[3]);
        packet.flags = static_cast<char>(payload[4]);
        passthrough(input, &packet);
        return true;
      }
      case PLANK_TRANSPORT_INPUT_UTF8_TEXT: {
        if (payload_size > UTF8_TEXT_EVENT_MAX_COUNT) {
          return false;
        }
        std::vector<std::uint8_t> packet_storage(
          sizeof(NV_INPUT_HEADER) + payload_size
        );
        auto *packet = reinterpret_cast<NV_UNICODE_PACKET *>(packet_storage.data());
        packet->header.size = util::endian::big(
          static_cast<std::uint32_t>(sizeof(packet->header.magic) + payload_size)
        );
        std::copy_n(payload, payload_size, packet->text);
        passthrough(packet);
        return true;
      }
      case PLANK_TRANSPORT_INPUT_PEN: {
        if (payload_size != PLANK_TRANSPORT_INPUT_PEN_SIZE ||
            payload[6] != 0 || payload[7] != 0 ||
            plank_transport_input_read_u32(payload + 28) != 0) {
          return false;
        }
        SS_PEN_PACKET packet {};
        packet.eventType = payload[0];
        packet.toolType = payload[1];
        packet.penButtons = payload[2];
        packet.tilt = payload[3];
        packet.rotation = util::endian::little(
          plank_transport_input_read_u16(payload + 4)
        );
        to_netfloat(plank_transport_input_read_float(payload + 8), packet.x);
        to_netfloat(plank_transport_input_read_float(payload + 12), packet.y);
        to_netfloat(plank_transport_input_read_float(payload + 16), packet.pressureOrDistance);
        to_netfloat(plank_transport_input_read_float(payload + 20), packet.contactAreaMajor);
        to_netfloat(plank_transport_input_read_float(payload + 24), packet.contactAreaMinor);
        select_normalized_pen_backend(input);
        passthrough(input, &packet);
        return true;
      }
      case PLANK_TRANSPORT_INPUT_RAW_HID_WACOM: {
        if (payload_size < sizeof(PLANK_RAW_HID_WIRE_HEADER) ||
            payload_size > sizeof(PLANK_RAW_HID_WIRE_HEADER) + PLANK_RAW_HID_MAX_PAYLOAD_SIZE) {
          return false;
        }
        std::vector<std::uint8_t> frame(payload, payload + payload_size);
        return handle_raw_hid_frame(input, frame);
      }
      default:
        return false;
    }
  }
#endif

  /**
   * @brief Release every mouse button still held when the stream disconnects.
   */
  void reset_mouse_buttons() {
    for (int button = 0; button < mouse_press.size(); ++button) {
      if (mouse_press[button]) {
        platf::button_mouse(platf_input, button, true);
        mouse_press[button] = false;
      }
    }
  }

  /**
   * @brief Release every pressed keyboard key tracked by Sunshine.
   */
  void reset_keyboard_keys() {
    for (auto &[key, pressed] : key_press) {
      if (pressed) {
        platf::keyboard_update(platf_input, vk_from_kpid(key) & 0x00FF, true, flags_from_kpid(key));
        pressed = false;
      }
    }
  }

  /**
   * @brief Reset all pressed input state for a disconnected stream.
   *
   * @param input Retained stream input state to reset.
   */
  void reset_input_state(const std::shared_ptr<input_t> &input, const std::uint64_t connection_id) {
    if (input->connection_id.load() != connection_id) {
      BOOST_LOG(debug) << "Skipping stale input reset for connection "sv << connection_id;
      return;
    }

    task_pool.cancel(key_press_repeat_id);
    reset_mouse_buttons();
    reset_keyboard_keys();
    platf::pen_input_t pen {};
    pen.eventType = LI_TOUCH_EVENT_CANCEL_ALL;
    pen.toolType = LI_TOOL_TYPE_UNKNOWN;
    platf::pen_update(input->client_context.get(), {}, pen);
    // Keep the host UHID/XInput endpoints stable across stream reservations.
    // The replacement transport must re-present the same USB
    // identity and descriptors before tablet reports are accepted again.
    input->raw_hid_tablet->suspend();
  }

  /**
   * @brief Reset the object to its initial empty state.
   */
  void reset(std::shared_ptr<input_t> &input, const std::uint64_t connection_id) {
    std::lock_guard lock {input_state_mutex};
    reset_input_state(input, connection_id);
  }

  namespace {
    /**
     * @brief Release desktop-owned devices after the input workers have stopped.
     *
     * This is subsystem shutdown, never stream/reservation cleanup. Destroy
     * devices outside the storage lock and before releasing the platform backend.
     */
    void clear_desktop_input() {
      retained_input_map_t inputs;
      {
        auto &state = retained_input_state();
        std::lock_guard lock {state.mutex};
        state.inputs.swap(inputs);
      }
    }
  }  // namespace

  /**
   * @brief RAII helper that runs shutdown cleanup when destroyed.
   */
  class deinit_t: public platf::deinit_t {
  public:
    /**
     * @brief Destroy the input subsystem deinitializer.
     */
    ~deinit_t() override {
      clear_desktop_input();
      platf_input.reset();
    }
  };

  /**
   * @brief Initialize the platform input backend.
   */
  [[nodiscard]] std::unique_ptr<platf::deinit_t> init() {
    platf_input = platf::input();

    return std::make_unique<deinit_t>();
  }

  /**
   * @brief Allocate and initialize platform input state for a stream.
   */
  std::shared_ptr<input_t> alloc(safe::mail_t mail, std::string session_id, std::uint64_t &connection_id) {
    std::lock_guard state_lock {input_state_mutex};
    std::shared_ptr<input_t> input;
    bool resumed = false;
    {
      auto &state = retained_input_state();
      std::lock_guard lock {state.mutex};
      const auto iter = state.inputs.find(session_id);
      if (iter != state.inputs.end()) {
        input = iter->second;
        resumed = true;
      } else {
        input = std::make_shared<input_t>(
          mail->event<input::touch_port_t>(mail::touch_port),
          mail->queue<std::vector<std::uint8_t>>(mail::raw_hid_feedback)
        );
        state.inputs.try_emplace(std::move(session_id), input);
      }
    }

    if (resumed) {
      // A replacement can win the state lock before the old disconnect. End
      // its held input now; the old reset will correctly become a no-op once
      // this new lease is published. Raw device identities remain retained.
      reset_input_state(input, input->connection_id.load());
    }
    connection_id = ++input->connection_id;
    if (connection_id == 0) {
      connection_id = ++input->connection_id;
    }

    if (resumed) {
      // Publish the entire binding before starting the native input receiver.
      rebind_input(input, mail);
    }

    if (!enable_num_lock()) {
      BOOST_LOG(debug) << "Num Lock will be enabled when the authenticated X11 desktop becomes available"sv;
    }

    // Workaround to ensure new frames will be captured when a client connects
    task_pool.pushDelayed([]() {
      std::lock_guard lock {input_state_mutex};
      platf::move_mouse(platf_input, 1, 1);
      platf::move_mouse(platf_input, -1, -1);
    },
                          100ms);

    return input;
  }

#ifdef SUNSHINE_TESTS
  namespace testing {
    void set_platform_input(platf::input_t input) {
      clear_desktop_input();
      platf_input = std::move(input);
    }

    bool handle_raw_hid(const std::shared_ptr<input_t> &input, const std::vector<std::uint8_t> &frame) {
      std::lock_guard lock {input_state_mutex};
      return input && handle_raw_hid_frame(input, frame);
    }

    std::uint16_t raw_hid_generation(const std::shared_ptr<input_t> &input) {
      return input ? input->raw_hid_tablet->active_generation() : 0;
    }

    raw_hid::tablet_t &raw_tablet(const std::shared_ptr<input_t> &input) {
      return *input->raw_hid_tablet;
    }

    bool normalized_pen_enabled(const std::shared_ptr<input_t> &input) {
      return input && platf::normalized_pen_enabled(input->client_context.get());
    }

    void select_normalized_pen(const std::shared_ptr<input_t> &input) {
      std::lock_guard lock {input_state_mutex};
      if (input) {
        select_normalized_pen_backend(input);
      }
    }

    void handle_keyboard(const std::shared_ptr<input_t> &input, const std::uint16_t key_code, const bool release) {
      std::lock_guard lock {input_state_mutex};
      if (!input) {
        return;
      }
      NV_KEYBOARD_PACKET packet {};
      packet.header.magic = util::endian::little<std::uint32_t>(release ? KEY_UP_EVENT_MAGIC : KEY_DOWN_EVENT_MAGIC);
      packet.keyCode = static_cast<short>(key_code);
      auto mutable_input = input;
      passthrough(mutable_input, &packet);
    }

    void handle_mouse_button(const std::shared_ptr<input_t> &input, const std::uint8_t button, const bool release) {
      std::lock_guard lock {input_state_mutex};
      if (!input) {
        return;
      }
      NV_MOUSE_BUTTON_PACKET packet {};
      packet.header.magic = util::endian::little<std::uint32_t>(
        release ? MOUSE_BUTTON_UP_EVENT_MAGIC_GEN5 : MOUSE_BUTTON_DOWN_EVENT_MAGIC_GEN5
      );
      packet.button = button;
      auto mutable_input = input;
      passthrough(mutable_input, &packet);
    }

    std::uint16_t last_keyboard_code() {
      if (!platf_input) {
        return 0;
      }
      const auto &context = platf::virtualhid::get_input_context(platf_input);
      return context.keyboard ? context.keyboard->last_submitted_event().key_code : 0;
    }

    void with_input_lock(const std::function<void()> &action) {
      std::lock_guard lock {input_state_mutex};
      action();
    }

    platf::client_input_t *client_context(const std::shared_ptr<input_t> &input) {
      return input->client_context.get();
    }
  }  // namespace testing
#endif
}  // namespace input
