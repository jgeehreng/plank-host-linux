/**
 * @file src/auth/web_auth.h
 * @brief Network-to-broker PAM conversation and session-token state.
 */
#pragma once

#include "pam_client.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace plank::auth {
  /**
   * @brief Abstract one PAM conversation for testable web-session orchestration.
   */
  class conversation_i {
  public:
    /**
     * @brief Destroy the conversation and close any PAM session.
     */
    virtual ~conversation_i() = default;

    /**
     * @brief Start authentication.
     *
     * @param transaction_id Broker transaction identifier.
     * @param username Operating-system account.
     * @param remote_host Auditable client address.
     * @return First challenge or terminal result.
     */
    virtual step_t begin(std::uint64_t transaction_id, std::string_view username, std::string_view remote_host) = 0;

    /**
     * @brief Submit responses for the last challenge.
     *
     * @param responses One response per PAM message.
     * @return Next challenge or terminal result.
     */
    virtual step_t respond(std::vector<std::string> responses) = 0;

    /** @brief Request nonblocking, thread-safe cancellation of the pending operation. */
    virtual void cancel() noexcept = 0;
  };

  /**
   * @brief Result returned to an HTTPS authentication handler.
   */
  struct web_auth_step_t {
    step_t::state_e state = step_t::state_e::denied;  ///< Conversation state.
    std::string conversation_id;  ///< Opaque ID for the next response.
    std::string session_token;  ///< Opaque bearer token after success.
    std::vector<prompt_t> prompts;  ///< PAM messages for a challenge.
    phase_e phase = phase_e::protocol;  ///< Terminal phase.
    int pam_status = -1;  ///< Terminal PAM status.
  };

  /**
   * @brief Own pending PAM conversations and authenticated session tokens.
   */
  class web_auth_manager_t {
  public:
    using clock_t = std::chrono::steady_clock;  ///< Monotonic expiry clock.
    using conversation_factory_t = std::function<std::unique_ptr<conversation_i>()>;  ///< Conversation constructor.
    using random_t = std::function<std::string(std::size_t)>;  ///< Opaque identifier generator.
    using now_t = std::function<clock_t::time_point()>;  ///< Injectable clock.

    /**
     * @brief Create a web authentication manager.
     *
     * @param factory PAM conversation factory.
     * @param random Cryptographically secure random-string generator.
     * @param now Monotonic time provider.
     * @param conversation_lifetime Maximum time between PAM responses.
     * @param token_lifetime Maximum token lifetime before stream ownership.
     */
    web_auth_manager_t(conversation_factory_t factory, random_t random, now_t now = clock_t::now, std::chrono::seconds conversation_lifetime = std::chrono::seconds {120}, std::chrono::seconds token_lifetime = std::chrono::seconds {300});

    /**
     * @brief Begin a PAM conversation for one TLS peer.
     *
     * @param username Requested account.
     * @param remote_host Normalized TLS peer address.
     * @param cancellation Optional request-owner cancellation.
     * @return Challenge or terminal result.
     */
    web_auth_step_t begin(std::string_view username, std::string_view remote_host, std::stop_token cancellation = {});

    /**
     * @brief Advance an existing PAM conversation.
     *
     * @param conversation_id Opaque conversation identifier.
     * @param remote_host Normalized TLS peer address; must match the creator.
     * @param responses One response per PAM message.
     * @param cancellation Optional request-owner cancellation.
     * @return Next challenge or terminal result.
     */
    web_auth_step_t respond(std::string_view conversation_id, std::string_view remote_host, std::vector<std::string> responses, std::stop_token cancellation = {});

    /**
     * @brief Validate a session token for its originating peer.
     *
     * @param token Opaque bearer token.
     * @param remote_host Normalized TLS peer address.
     * @return True when the token is active and peer-bound.
     */
    bool authorize(std::string_view token, std::string_view remote_host);

    /**
     * @brief Return the authenticated account bound to an active token.
     *
     * @param token Opaque bearer token.
     * @param remote_host Normalized TLS peer address.
     * @return Requested PAM account, or no value when authorization fails.
     */
    std::optional<std::string> identity(std::string_view token, std::string_view remote_host);

    /**
     * @brief Attach an authenticated PAM session to a stream.
     *
     * The first claim transfers the manager's strong ownership to the caller.
     * Additional concurrent claims share that live session. Once every stream
     * releases it, the PAM session closes and the token cannot claim it again.
     *
     * @param token Opaque bearer token.
     * @param remote_host Normalized TLS peer address.
     * @return Shared session lifetime handle, or null when unavailable.
     */
    std::shared_ptr<conversation_i> claim(std::string_view token, std::string_view remote_host);

    /**
     * @brief Revoke a token or cancel a pending conversation, including in-flight work.
     *
     * @param token Opaque bearer token.
     */
    void cancel(std::string_view token);

    /** @brief Cancel all manager-owned conversations during worker shutdown. */
    void cancel_all();

    /**
     * @brief Remove expired conversations and sessions.
     */
    void expire();

  private:
    struct entry_t {
      std::string remote_host;  ///< TLS peer bound to the entry.
      std::string username;  ///< PAM-authenticated operating-system account.
      clock_t::time_point expires;  ///< Entry expiry.
      std::shared_ptr<conversation_i> conversation;  ///< Manager-owned broker connection before launch.
      std::weak_ptr<conversation_i> claimed_session;  ///< Session owned by active streams after launch.
      bool busy = false;  ///< A begin/respond operation is running outside the mutex.
      bool cancelled = false;  ///< Revoked entries cannot publish a late result.
    };

    using entry_ptr_t = std::shared_ptr<entry_t>;  ///< Stable identity while an operation is in flight.

    /** @brief Defer cancellation/destruction until after the state lock is released. */
    struct retired_t {
      std::vector<entry_ptr_t> entries;  ///< Entries retired under the state lock.
      ~retired_t();
    };

    /**
     * @brief Convert a broker step into managed web state.
     *
     * @param step Broker result.
     * @param id Pending conversation ID.
     * @param entry Conversation ownership.
     * @return Network-facing step.
     */
    web_auth_step_t retain(step_t step, const std::string &id, const entry_ptr_t &entry);

    /**
     * @brief Remove expired entries while the mutex is held.
     * @param retired Collect entries for cleanup after unlocking.
     */
    void expire_locked(retired_t &retired);

    conversation_factory_t factory_;  ///< PAM conversation factory.
    random_t random_;  ///< Secure opaque-string generator.
    now_t now_;  ///< Monotonic time provider.
    std::chrono::seconds conversation_lifetime_;  ///< Pending-conversation lifetime.
    std::chrono::seconds token_lifetime_;  ///< Authenticated token lifetime.
    std::uint64_t next_transaction_ = 1;  ///< Local broker correlation counter.
    std::mutex mutex_;  ///< Protects all maps and counters.
    std::unordered_map<std::string, entry_ptr_t> conversations_;  ///< Pending and in-flight PAM exchanges; both consume capacity.
    std::unordered_map<std::string, entry_ptr_t> tokens_;  ///< Authenticated PAM sessions.
  };

  /**
   * @brief Create the production PAM conversation factory.
   *
   * @return Factory suitable for @ref web_auth_manager_t.
   */
  web_auth_manager_t::conversation_factory_t pam_conversation_factory();

  /**
   * @brief Generate a cryptographically random hexadecimal identifier.
   *
   * @param bytes Random byte count before hexadecimal encoding.
   * @return Lowercase hexadecimal value, or an empty string on failure.
   */
  std::string secure_random_hex(std::size_t bytes);

  /**
   * @brief Resolve a validated operating-system account through NSS.
   *
   * Name Service Switch resolution supports both local and configured domain
   * @param username PAM-authenticated operating-system account.
   * @return Resolved UID, or no value for an invalid/missing account.
   */
  std::optional<uid_t> account_uid(std::string_view username);

  /**
   * Authorize a PAM account for the desktop owned by this worker.
   *
   * The root machine worker accepts any non-root PAM account at the local GDM
   * greeter. Once a user session owns seat0, the account UID must match it.
   */
  bool account_authorized_for_desktop(std::string_view username);
}  // namespace plank::auth
