/**
 * @file src/session/gdm_login.h
 * @brief Start a GDM user session after PLANK PAM succeeds at the greeter.
 */
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace plank::session {
  /**
   * @brief Return whether a PAM account name is safe to hand to GDM.
   *
   * @param username Authenticated PAM account.
   * @return True when the name is non-empty, bounded, and has no NULs or line breaks.
   */
  bool valid_gdm_username(std::string_view username);

  /**
   * @brief Ask GDM 40 to start a graphical session for an already-authenticated account.
   *
   * Talks to GDM's private UserVerifier as the greeter user. Secrets are used once
   * on that bus and wiped; they are never logged or written to settings.
   *
   * @param username Authenticated PAM account, not an NSS FQDN.
   * @param secrets PAM prompt responses still in worker memory, usually the password.
   * @return True when GDM accepted StartSessionWhenReady.
   */
  bool complete_gdm_login(std::string_view username, std::vector<std::string> &secrets);
}  // namespace plank::session
