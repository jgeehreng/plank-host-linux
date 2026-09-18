/**
 * @file src/session/session_context.h
 * @brief Logind-backed graphical-session selection for PLANK.
 */
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <sys/types.h>

namespace plank::session {
  // Private supervisor command: announce a confirmed greeter-to-user handoff,
  // then use the worker's normal shutdown path. Never a request from a client.
  inline constexpr std::string_view desktop_handoff_command = "PLANK-DESKTOP-HANDOFF-1";
  struct descriptor_t {
    std::string id;
    uid_t uid {};
    std::string seat;
    std::string type;
    std::string session_class;
    std::string state;
    bool active {};
    bool remote {};
  };

  struct environment_t {
    std::string display;
    std::string xauthority;
    std::string runtime_directory;
    std::string dbus_address;
    std::string pulse_server;
    std::string pulse_cookie;
  };

  struct update_t {
    std::uint64_t generation {};
    descriptor_t session;
    environment_t environment;
  };

  struct display_request_t {
    enum class action_t {
      acquire,
      activate,
      release,
    } action {action_t::acquire};
    std::string layout;
    std::string mode_1;
    std::string mode_2;
    uid_t account_uid {};
  };

  struct runtime_display_state_t {
    std::string layout;
    std::string mode_1;
    std::string mode_2;
    uid_t lease_uid {};
  };

  enum class display_request_status {
    submitted,
    wrong_user,
    unavailable,
    invalid,
  };

  enum class startup_layout_t {
    physical,
    virtual_display,
    invalid,
  };

  class supervisor_control_t {
  public:
    virtual ~supervisor_control_t() = default;
  };

  /** Return true only for a supported, local active seat0 session. */
  bool eligible_graphical_session(const descriptor_t &session);

  /** Return a UI-only stage when the active session matches the worker attachment. */
  std::string_view desktop_stage(const descriptor_t &attached, const descriptor_t &active);

  /** Query the confirmed worker stage; never grants desktop or authentication access. */
  std::string confirmed_desktop_stage();

  /** Query one logind session. */
  std::optional<descriptor_t> describe(std::string_view session_id);

  /** Query and validate the currently active session on seat0. */
  std::optional<descriptor_t> active_seat0_graphical_session();

  /**
   * Find DISPLAY and Xauthority in a process belonging to the selected
   * logind session. Only a small environment whitelist is returned.
   */
  std::optional<environment_t> discover_environment(const descriptor_t &session);

  /** Authorize an account against the supervisor-controlled active seat0 session. */
  bool supervisor_attests_account_for_active_seat0(uid_t account_uid);

  /** Encode or decode one bounded supervisor desktop-attachment update. */
  std::string session_update_message(const update_t &update);
  std::optional<update_t> parse_session_update(std::string_view message);

  /** Encode or decode one bounded worker-to-supervisor display request. */
  std::string display_request_message(const display_request_t &request);
  std::optional<display_request_t> parse_display_request(std::string_view message);

  /** Encode, decode, or read the supervisor-owned live display-layout marker. */
  std::string runtime_display_state_message(const runtime_display_state_t &state);
  std::optional<runtime_display_state_t> parse_runtime_display_state(
    std::string_view message
  );
  std::optional<runtime_display_state_t> read_runtime_display_state(
    std::string_view path
  );

  /** Read the intended secondary-monitor visibility from an owned Xorg overlay. */
  std::optional<bool> secondary_output_visible_from_overlay(std::string_view overlay);

  /** Read the administrator-owned startup display policy; malformed input fails closed. */
  startup_layout_t configured_startup_layout(std::string_view config_path);

  /** Request a display transition from GDM or the authenticated user's desktop. */
  display_request_status request_display_transition(const display_request_t &request);

  /** Mark a temporary physical-display lease active once native setup allocates its stream. */
  display_request_status activate_display_lease(uid_t account_uid);

  /** Release a temporary physical-display lease when its final stream ends. */
  display_request_status release_display_lease(uid_t account_uid);

  /** Begin monitoring the inherited, root-authenticated supervisor channel. */
  std::unique_ptr<supervisor_control_t> start_supervisor_control(
    std::function<void(std::uint64_t)> on_reattach,
    std::function<void()> on_desktop_handoff = {}
  );

  /** Return the most recently accepted desktop attachment generation. */
  std::uint64_t desktop_generation();
}  // namespace plank::session
