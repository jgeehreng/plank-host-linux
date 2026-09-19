/**
 * @file src/session/gdm_login.h
 * @brief Start a GDM user session after PLANK PAM succeeds at the greeter.
 */
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace plank::session {
  constexpr std::string_view gdm_login_socket_path = "/run/plank/gdm/login.sock";
  constexpr std::size_t maximum_gdm_username = 256;
  constexpr std::size_t maximum_gdm_secret = 256;
  constexpr std::size_t maximum_gdm_secrets = 4;
  constexpr std::size_t maximum_gdm_session_id = 64;

  /**
   * @brief Encoded GDM helper result returned to the media worker.
   */
  enum class gdm_login_step : unsigned char {
    ok = 1,
    join_failed = 2,
    open_session_failed = 3,
    begin_failed = 4,
    verify_timeout = 5,
    verify_failed = 6,
    start_failed = 7,
    no_gdm_account = 8,
    helper_unavailable = 9,
    connect_failed = 10,
  };

  /**
   * @brief Return whether a PAM account name is safe to hand to GDM.
   *
   * @param username Authenticated PAM account.
   * @return True when the name is non-empty, bounded, and has no NULs or line breaks.
   */
  inline bool valid_gdm_username(std::string_view username) {
    return !username.empty() && username.size() <= maximum_gdm_username &&
           username.find('\0') == std::string_view::npos &&
           username.find('\n') == std::string_view::npos &&
           username.find('\r') == std::string_view::npos;
  }

  /**
   * @brief Ask GDM 40 to start a graphical session for an already-authenticated account.
   *
   * The capability-bounded media worker forwards the PAM identity to
   * `plank-gdm-login`, which joins the greeter session as `gdm`. Secrets are
   * used once on GDM's private bus and wiped; they are never logged.
   *
   * @param username Authenticated PAM account.
   * @param secrets PAM prompt responses still in worker memory, usually the password.
   * @return True when GDM accepted StartSessionWhenReady.
   */
  bool complete_gdm_login(std::string_view username, std::vector<std::string> &secrets);
}  // namespace plank::session
