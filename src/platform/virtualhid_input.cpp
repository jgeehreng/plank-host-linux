/**
 * @file src/platform/virtualhid_input.cpp
 * @brief Definitions for libvirtualhid-backed input helpers.
 */

// standard includes
#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <mutex>
#include <numbers>
#include <optional>
#include <random>
#include <string_view>
#include <utility>

// local includes
#include "src/config.h"
#include "src/logging.h"
#include "virtualhid_input.h"

using namespace std::literals;

namespace platf::virtualhid {
  namespace {

    void log_failure(std::string_view operation, const lvh::OperationStatus &status) {
      if (!status.ok()) {
        BOOST_LOG(warning) << operation << ": "sv << status.message();
      }
    }

    std::optional<lvh::MouseButton> mouse_button(int button) {
      using enum lvh::MouseButton;

      switch (button) {
        case BUTTON_LEFT:
          return left;
        case BUTTON_MIDDLE:
          return middle;
        case BUTTON_RIGHT:
          return right;
        case BUTTON_X1:
          return side;
        case BUTTON_X2:
          return extra;
        default:
          BOOST_LOG(warning) << "Unknown mouse button: "sv << button;
          return std::nullopt;
      }
    }

    lvh::PointerViewport pointer_viewport(const touch_port_t &touch_port) {
      return {
        .offset_x = touch_port.offset_x,
        .offset_y = touch_port.offset_y,
        .width = touch_port.width,
        .height = touch_port.height,
      };
    }

    lvh::KeyboardEvent keyboard_event(std::uint16_t modcode, bool release, std::uint8_t flags) {
      lvh::KeyboardEvent event {
        .key_code = modcode,
        .pressed = !release,
      };

#ifdef _WIN32
      event.uses_normalized_key_code = (static_cast<std::byte>(flags) & static_cast<std::byte>(SS_KBE_FLAG_NON_NORMALIZED)) == std::byte {};
      event.prefer_native_scan_code = config::input.always_send_scancodes;
#else
      (void) flags;
#endif
      return event;
    }

    lvh::PenToolType pen_tool(std::uint8_t tool) {
      using enum lvh::PenToolType;

      switch (tool) {
        case LI_TOOL_TYPE_PEN:
          return pen;
        case LI_TOOL_TYPE_ERASER:
          return eraser;
        case LI_TOOL_TYPE_UNKNOWN:
        default:
          return unchanged;
      }
    }

  }  // namespace

  input_context_t::input_context_t():
      input_context_t {lvh::BackendKind::platform_default} {}

  input_context_t::input_context_t(lvh::BackendKind backend):
      runtime {create_runtime(backend)} {
    if (!runtime) {
      BOOST_LOG(warning) << "Unable to create libvirtualhid runtime"sv;
      return;
    }

    const auto &capabilities = runtime->capabilities();
    if (capabilities.supports_keyboard) {
      lvh::CreateKeyboardOptions options;
      options.profile = lvh::profiles::keyboard();
      options.stable_id = "plank-keyboard";
      auto created = runtime->create_keyboard(options);
      if (created) {
        keyboard = std::move(created.keyboard);
      } else {
        log_failure("create libvirtualhid keyboard"sv, created.status);
      }
    }
    if (capabilities.supports_mouse) {
      lvh::CreateMouseOptions options;
      options.profile = lvh::profiles::mouse();
      options.stable_id = "plank-mouse";
      auto created = runtime->create_mouse(options);
      if (created) {
        mouse = std::move(created.mouse);
      } else {
        log_failure("create libvirtualhid mouse"sv, created.status);
      }
    }
  }

  client_context_t::client_context_t(input_context_t &input):
      global {&input} {
    set_pen_tablet_enabled(*this, true);
  }

  void set_pen_tablet_enabled(client_context_t &context, const bool enabled) {
    if (!enabled) {
      context.pressed_pen_buttons.clear();
      context.pen.reset();
      return;
    }

    if (context.pen || !context.global || !context.global->runtime) {
      return;
    }

    const auto &capabilities = context.global->runtime->capabilities();
    if (capabilities.supports_pen_tablet) {
      lvh::CreatePenTabletOptions options;
      options.profile = lvh::profiles::pen_tablet();
      // Flame's tablet preferences and edge gestures use the Xorg Wacom
      // driver interface. Keep libvirtualhid's own USB identity, but expose
      // the generic pen as Wacom-compatible so the stock 70-wacom InputClass
      // can select that driver without any host Xorg configuration changes.
      options.profile.name = "PLANK Wacom Tablet";
      options.stable_id = "plank-pen-tablet";
      auto created = context.global->runtime->create_pen_tablet(options);
      if (created) {
        context.pen = std::move(created.pen_tablet);
      } else {
        log_failure("create libvirtualhid pen tablet"sv, created.status);
      }
    }
  }

  bool pen_tablet_enabled(const client_context_t &context) {
    return context.pen != nullptr;
  }

  std::unique_ptr<lvh::Runtime> create_runtime(lvh::BackendKind backend) {
    lvh::RuntimeOptions options;
    options.backend = backend;
    return lvh::Runtime::create(options);
  }

  void move_mouse(input_context_t &context, int delta_x, int delta_y) {
    if (context.mouse) {
      log_failure("submit libvirtualhid mouse movement"sv, context.mouse->move_relative(delta_x, delta_y));
    }
  }

  void abs_mouse(input_context_t &context, const touch_port_t &touch_port, float x, float y) {
    if (context.mouse) {
      log_failure(
        "submit libvirtualhid absolute mouse movement"sv,
        context.mouse->move_absolute(
          static_cast<std::int32_t>(std::lround(x)),
          static_cast<std::int32_t>(std::lround(y)),
          touch_port.width,
          touch_port.height
        )
      );
    }
  }

  void button_mouse(input_context_t &context, int button, bool release) {
    if (context.mouse) {
      const auto converted = mouse_button(button);
      if (!converted) {
        return;
      }

      log_failure("submit libvirtualhid mouse button"sv, context.mouse->button(*converted, !release));
    }
  }

  void scroll(input_context_t &context, int high_res_distance) {
    if (context.mouse) {
      log_failure("submit libvirtualhid vertical scroll"sv, context.mouse->vertical_scroll(high_res_distance));
    }
  }

  void hscroll(input_context_t &context, int high_res_distance) {
    if (context.mouse) {
      log_failure("submit libvirtualhid horizontal scroll"sv, context.mouse->horizontal_scroll(high_res_distance));
    }
  }

  void keyboard_update(input_context_t &context, std::uint16_t modcode, bool release, std::uint8_t flags) {
    if (context.keyboard) {
      log_failure("submit libvirtualhid keyboard input"sv, context.keyboard->submit(keyboard_event(modcode, release, flags)));
    }
  }

  void unicode(input_context_t &context, const char *utf8, int size) {
    if (context.keyboard && utf8 && size > 0) {
      log_failure("submit libvirtualhid text input"sv, context.keyboard->type_text({.text = std::string {utf8, static_cast<std::size_t>(size)}}));
    }
  }

  /**
   * @brief Apply pen buttons and, for motion/contact events, tool state.
   * @param context Per-client tablet and held-button state.
   * @param touch_port Host mapping viewport.
   * @param pen Normalized pen event; button-only events preserve tip/hover state.
   */
  void pen_update(client_context_t &context, const touch_port_t &touch_port, const pen_input_t &pen) {
    if (!context.pen) {
      return;
    }

    const bool leaving = pen.eventType == LI_TOUCH_EVENT_CANCEL_ALL ||
                         pen.eventType == LI_TOUCH_EVENT_CANCEL ||
                         pen.eventType == LI_TOUCH_EVENT_HOVER_LEAVE;
    const auto pen_buttons = static_cast<std::byte>(leaving ? 0 : pen.penButtons);
    const std::array button_states {
      std::pair {lvh::PenButton::primary, (pen_buttons & static_cast<std::byte>(LI_PEN_BUTTON_PRIMARY)) != std::byte {}},
      std::pair {lvh::PenButton::secondary, (pen_buttons & static_cast<std::byte>(LI_PEN_BUTTON_SECONDARY)) != std::byte {}},
      std::pair {lvh::PenButton::tertiary, (pen_buttons & static_cast<std::byte>(LI_PEN_BUTTON_TERTIARY)) != std::byte {}},
    };
    for (const auto &[button, pressed] : button_states) {
      const auto was_pressed = context.pressed_pen_buttons.contains(button);
      if (pressed == was_pressed) {
        continue;
      }

      const auto status = context.pen->button(button, pressed);
      log_failure("submit libvirtualhid pen button"sv, status);
      if (!status.ok()) {
        // Retain the last accepted state so the next report retries this edge.
        continue;
      }
      if (pressed) {
        context.pressed_pen_buttons.insert(button);
      } else {
        context.pressed_pen_buttons.erase(button);
      }
    }

    if (pen.eventType == LI_TOUCH_EVENT_BUTTON_ONLY) {
      // pressureOrDistance has no contact discriminator in this event. Do
      // not turn a barrel-button change during a stroke into a hover/release.
      return;
    }

    using enum lvh::PointerTransition;
    auto transition = update;
    switch (pen.eventType) {
      case LI_TOUCH_EVENT_CANCEL:
      case LI_TOUCH_EVENT_CANCEL_ALL:
        transition = cancel;
        break;
      case LI_TOUCH_EVENT_UP:
        transition = release;
        break;
      case LI_TOUCH_EVENT_HOVER_LEAVE:
        transition = leave;
        break;
      default:
        break;
    }

    auto rotation = pen.rotation;
    if (rotation != LI_ROT_UNKNOWN) {
      rotation %= 360;
    }

    float tilt_x = 0.0F;
    float tilt_y = 0.0F;
    if (pen.tilt != LI_TILT_UNKNOWN && rotation != LI_ROT_UNKNOWN) {
      const auto rotation_rads = static_cast<float>(rotation) * std::numbers::pi_v<float> / 180.0F;
      const auto tilt_rads = static_cast<float>(pen.tilt) * std::numbers::pi_v<float> / 180.0F;
      const auto r = std::sin(tilt_rads);
      const auto z = std::cos(tilt_rads);

      tilt_x = std::atan2(std::sin(-rotation_rads) * r, z) * 180.0F / std::numbers::pi_v<float>;
      tilt_y = std::atan2(std::cos(-rotation_rads) * r, z) * 180.0F / std::numbers::pi_v<float>;
    }

    const auto is_touching = transition == update &&
                             (pen.eventType == LI_TOUCH_EVENT_DOWN || pen.eventType == LI_TOUCH_EVENT_MOVE);
    lvh::PenToolState state;
    state.tool = pen_tool(pen.toolType);
    state.x = std::clamp(pen.x, 0.0F, 1.0F);
    state.y = std::clamp(pen.y, 0.0F, 1.0F);
    state.pressure = is_touching ? std::clamp(pen.pressureOrDistance, 0.0F, 1.0F) : -1.0F;
    state.distance = is_touching ? -1.0F : std::clamp(pen.pressureOrDistance, 0.0F, 1.0F);
    state.tilt_x = tilt_x;
    state.tilt_y = tilt_y;
    state.transition = transition;
    state.viewport = pointer_viewport(touch_port);
    const auto status = context.pen->place_tool(state);
    log_failure("submit libvirtualhid pen state"sv, status);
    if (leaving && status.ok()) {
      // Linux's completed leave/cancel also releases all barrel buttons.
      context.pressed_pen_buttons.clear();
    }
  }

}  // namespace platf::virtualhid

namespace platf {

#ifndef _WIN32
  /**
   * @brief Global libvirtualhid devices shared by clients.
   */
  struct input_raw_t {
    virtualhid::input_context_t virtualhid;  ///< libvirtualhid input context.
  };

  namespace {

    /**
     * @brief Per-client libvirtualhid devices.
     */
    struct client_input_raw_t: client_input_t {
      /**
       * @brief Create per-client libvirtualhid devices.
       *
       * @param input Platform input backend that receives the event.
       */
      explicit client_input_raw_t(input_t &input):
          virtualhid {input->virtualhid} {}

      virtualhid::client_context_t virtualhid;  ///< libvirtualhid client context.
    };

  }  // namespace

  input_t input() {
    return {new input_raw_t {}};
  }

  std::unique_ptr<client_input_t> allocate_client_input_context(input_t &input) {
    return std::make_unique<client_input_raw_t>(input);
  }

  void freeInput(input_raw_t *input) {
    std::default_delete<input_raw_t> {}(input);
  }

  virtualhid::input_context_t &virtualhid::get_input_context(input_t &input) {
    return input->virtualhid;
  }

  virtualhid::client_context_t &virtualhid::get_client_context(client_input_t *input) {
    return static_cast<client_input_raw_t *>(input)->virtualhid;
  }
#endif

  void move_mouse(input_t &input, int deltaX, int deltaY) {
    virtualhid::move_mouse(virtualhid::get_input_context(input), deltaX, deltaY);
  }

  void abs_mouse(input_t &input, const touch_port_t &touch_port, float x, float y) {
    virtualhid::abs_mouse(virtualhid::get_input_context(input), touch_port, x, y);
  }

  void button_mouse(input_t &input, int button, bool release) {
    virtualhid::button_mouse(virtualhid::get_input_context(input), button, release);
  }

  void scroll(input_t &input, int high_res_distance) {
    virtualhid::scroll(virtualhid::get_input_context(input), high_res_distance);
  }

  void hscroll(input_t &input, int high_res_distance) {
    virtualhid::hscroll(virtualhid::get_input_context(input), high_res_distance);
  }

  void keyboard_update(input_t &input, uint16_t modcode, bool release, uint8_t flags) {
    virtualhid::keyboard_update(virtualhid::get_input_context(input), modcode, release, flags);
  }

  void unicode(input_t &input, const char *utf8, int size) {
    virtualhid::unicode(virtualhid::get_input_context(input), utf8, size);
  }

  void set_normalized_pen_enabled(client_input_t *input, const bool enabled) {
    if (!input) {
      return;
    }
    virtualhid::set_pen_tablet_enabled(virtualhid::get_client_context(input), enabled);
  }

  bool normalized_pen_enabled(client_input_t *input) {
    return input && virtualhid::pen_tablet_enabled(virtualhid::get_client_context(input));
  }

  void pen_update(client_input_t *input, const touch_port_t &touch_port, const pen_input_t &pen) {
    virtualhid::pen_update(virtualhid::get_client_context(input), touch_port, pen);
  }

}  // namespace platf
