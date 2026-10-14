/**
 * @file src/auth/web_auth.cpp
 * @brief Network-to-broker PAM conversation and session-token state.
 */

#include "web_auth.h"

#include "../session/session_context.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <openssl/rand.h>
#include <pwd.h>
#include <unistd.h>
#include <utility>

namespace plank::auth {
  namespace {
    /**
     * @brief Production adapter around @ref pam_client_t.
     */
    class pam_conversation_t: public conversation_i {
    public:
      step_t begin(std::uint64_t transaction_id, std::string_view username, std::string_view remote_host) override {
        return client_.begin(transaction_id, username, remote_host, "plank");
      }

      step_t respond(std::vector<std::string> responses) override {
        return client_.respond(std::move(responses));
      }

      void cancel() noexcept override {
        client_.cancel();
      }

    private:
      pam_client_t client_;  ///< Local broker connection.
    };

    /**
     * @brief Securely erase response strings.
     *
     * @param responses Strings to erase.
     */
    void erase(std::vector<std::string> &responses) {
      for (auto &response : responses) {
        if (!response.empty()) {
          explicit_bzero(response.data(), response.size());
        }
      }
    }
  }  // namespace

  web_auth_manager_t::web_auth_manager_t(
    conversation_factory_t factory,
    random_t random,
    now_t now,
    std::chrono::seconds conversation_lifetime,
    std::chrono::seconds token_lifetime
  ):
      factory_ {std::move(factory)},
      random_ {std::move(random)},
      now_ {std::move(now)},
      conversation_lifetime_ {conversation_lifetime},
      token_lifetime_ {token_lifetime} {
  }

  web_auth_step_t web_auth_manager_t::begin(std::string_view username, std::string_view remote_host, std::stop_token cancellation) {
    if (cancellation.stop_requested() || username.empty() || username.size() > 256 || remote_host.empty() || remote_host.size() > 256) {
      return {};
    }
    entry_ptr_t entry;
    std::string id;
    std::uint64_t transaction_id;
    {
      retired_t retired;
      std::lock_guard lock {mutex_};
      expire_locked(retired);
      if (conversations_.size() + tokens_.size() >= 32) {
        return {};
      }
      entry = std::make_shared<entry_t>();
      entry->conversation = factory_();  // Construct only; broker work starts below.
      id = random_(24);
      if (!entry->conversation || id.empty() || conversations_.contains(id) || tokens_.contains(id)) {
        return {};
      }
      transaction_id = next_transaction_++;
      if (next_transaction_ == 0) {
        next_transaction_ = 1;
      }
      entry->remote_host = remote_host;
      entry->username = username;
      entry->expires = now_() + conversation_lifetime_;
      entry->busy = true;
      conversations_.emplace(id, entry);
    }
    std::stop_callback on_cancel {cancellation, [this, &id]() {
                                    cancel(id);
                                  }};
    step_t step {step_t::state_e::denied, {}, phase_e::protocol, -1};
    try {
      step = entry->conversation->begin(transaction_id, username, remote_host);
    } catch (...) {
      entry->conversation->cancel();
    }
    return retain(std::move(step), id, entry);
  }

  web_auth_step_t web_auth_manager_t::respond(std::string_view conversation_id, std::string_view remote_host, std::vector<std::string> responses, std::stop_token cancellation) {
    entry_ptr_t entry;
    const std::string id {conversation_id};
    {
      retired_t retired;
      std::lock_guard lock {mutex_};
      expire_locked(retired);
      const auto found = conversations_.find(id);
      if (found == conversations_.end() || found->second->remote_host != remote_host || found->second->busy || found->second->cancelled) {
        erase(responses);
        return {};
      }
      entry = found->second;
      entry->busy = true;
      entry->expires = now_() + conversation_lifetime_;
    }
    std::stop_callback on_cancel {cancellation, [this, &id]() {
                                    cancel(id);
                                  }};
    step_t step {step_t::state_e::denied, {}, phase_e::protocol, -1};
    try {
      step = entry->conversation->respond(std::move(responses));
    } catch (...) {
      erase(responses);
      entry->conversation->cancel();
    }
    return retain(std::move(step), id, entry);
  }

  bool web_auth_manager_t::authorize(std::string_view token, std::string_view remote_host) {
    return identity(token, remote_host).has_value();
  }

  std::optional<std::string> web_auth_manager_t::identity(
    std::string_view token,
    std::string_view remote_host
  ) {
    retired_t retired;
    std::lock_guard lock {mutex_};
    expire_locked(retired);
    const auto found = tokens_.find(std::string {token});
    if (found == tokens_.end() || found->second->remote_host != remote_host) {
      return std::nullopt;
    }
    if (!found->second->conversation && found->second->claimed_session.expired()) {
      tokens_.erase(found);
      return std::nullopt;
    }
    return found->second->username;
  }

  std::shared_ptr<conversation_i> web_auth_manager_t::claim(
    std::string_view token,
    std::string_view remote_host
  ) {
    retired_t retired;
    std::lock_guard lock {mutex_};
    expire_locked(retired);
    const auto found = tokens_.find(std::string {token});
    if (found == tokens_.end() || found->second->remote_host != remote_host) {
      return {};
    }
    if (found->second->conversation) {
      auto session = std::move(found->second->conversation);
      found->second->claimed_session = session;
      return session;
    }
    auto session = found->second->claimed_session.lock();
    if (!session) {
      tokens_.erase(found);
    }
    return session;
  }

  void web_auth_manager_t::cancel(std::string_view token) {
    retired_t retired;
    std::lock_guard lock {mutex_};
    const std::string id {token};
    if (const auto found = tokens_.find(id); found != tokens_.end()) {
      retired.entries.push_back(std::move(found->second));
      tokens_.erase(found);
    }
    if (const auto found = conversations_.find(id); found != conversations_.end()) {
      found->second->cancelled = true;
      retired.entries.push_back(found->second);
      // Keep in-flight work counted until it actually exits.
      if (!found->second->busy) {
        conversations_.erase(found);
      }
    }
  }

  void web_auth_manager_t::cancel_all() {
    retired_t retired;
    std::lock_guard lock {mutex_};
    for (auto &[id, entry] : conversations_) {
      entry->cancelled = true;
      retired.entries.push_back(entry);
    }
    std::erase_if(conversations_, [](const auto &item) {
      return !item.second->busy;
    });
    for (auto &[id, entry] : tokens_) {
      retired.entries.push_back(std::move(entry));
    }
    tokens_.clear();
  }

  void web_auth_manager_t::expire() {
    retired_t retired;
    std::lock_guard lock {mutex_};
    expire_locked(retired);
  }

  web_auth_step_t web_auth_manager_t::retain(step_t step, const std::string &id, const entry_ptr_t &entry) {
    retired_t retired;
    std::lock_guard lock {mutex_};
    expire_locked(retired);
    const auto found = conversations_.find(id);
    if (found == conversations_.end() || found->second != entry) {
      return {};
    }
    conversations_.erase(found);
    entry->busy = false;
    if (entry->cancelled) {
      return {};
    }
    web_auth_step_t output {
      step.state,
      {},
      {},
      std::move(step.prompts),
      step.phase,
      step.pam_status,
    };
    if (step.state == step_t::state_e::challenge) {
      output.conversation_id = id;
      entry->expires = now_() + conversation_lifetime_;
      conversations_.emplace(id, entry);
    } else if (step.state == step_t::state_e::authenticated) {
      std::string token = random_(32);
      if (token.empty() || conversations_.contains(token) || tokens_.contains(token)) {
        return {};
      }
      entry->expires = now_() + token_lifetime_;
      output.session_token = token;
      tokens_.emplace(std::move(token), entry);
    }
    return output;
  }

  web_auth_manager_t::retired_t::~retired_t() {
    for (const auto &entry : entries) {
      if (entry->conversation) {
        entry->conversation->cancel();
      }
    }
  }

  void web_auth_manager_t::expire_locked(retired_t &retired) {
    const auto time = now_();
    std::erase_if(conversations_, [time, &retired](const auto &item) {
      auto &entry = item.second;
      if (entry->expires > time || entry->cancelled) {
        return false;
      }
      entry->cancelled = true;
      retired.entries.push_back(entry);
      return !entry->busy;
    });
    std::erase_if(tokens_, [time, &retired](const auto &item) {
      if (item.second->expires > time) {
        return false;
      }
      retired.entries.push_back(item.second);
      return true;
    });
  }

  web_auth_manager_t::conversation_factory_t pam_conversation_factory() {
    return []() {
      return std::make_unique<pam_conversation_t>();
    };
  }

  std::string secure_random_hex(std::size_t bytes) {
    if (bytes == 0 || bytes > 64) {
      return {};
    }
    std::array<unsigned char, 64> random {};
    if (RAND_bytes(random.data(), static_cast<int>(bytes)) != 1) {
      return {};
    }
    constexpr std::string_view digits = "0123456789abcdef";
    std::string output(bytes * 2, '0');
    for (std::size_t index = 0; index < bytes; ++index) {
      output[index * 2] = digits[random[index] >> 4U];
      output[index * 2 + 1] = digits[random[index] & 0x0fU];
    }
    return output;
  }

  std::optional<uid_t> account_uid(std::string_view username) {
    if (username.empty() || username.find('\0') != std::string_view::npos || username.size() > 256) {
      return std::nullopt;
    }

    const std::string account {username};
    constexpr std::size_t minimum_buffer_size = 1024;
    constexpr std::size_t maximum_buffer_size = 1024 * 1024;
    const long recommended_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    std::size_t buffer_size = recommended_size > 0 ?
                                static_cast<std::size_t>(recommended_size) :
                                minimum_buffer_size;
    buffer_size = std::clamp(buffer_size, minimum_buffer_size, maximum_buffer_size);

    passwd record {};
    passwd *result = nullptr;
    std::vector<char> buffer(buffer_size);
    int status;
    do {
      status = getpwnam_r(account.c_str(), &record, buffer.data(), buffer.size(), &result);
      if (status != ERANGE || buffer.size() == maximum_buffer_size) {
        break;
      }
      buffer.resize(std::min(buffer.size() * 2, maximum_buffer_size));
    } while (true);

    if (status != 0 || result == nullptr) {
      return std::nullopt;
    }
    return result->pw_uid;
  }

  bool account_authorized_for_desktop(std::string_view username) {
    const auto uid = account_uid(username);
    return uid && plank::session::supervisor_attests_account_for_active_seat0(*uid);
  }
}  // namespace plank::auth
