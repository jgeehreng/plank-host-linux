/**
 * @file src/auth/pam_client.cpp
 * @brief Unprivileged Sunshine client for the local PAM broker.
 */

#include "pam_client.h"

#include "pam_broker_channel.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <system_error>
#include <unistd.h>
#include <utility>

namespace plank::auth {
  namespace {
    /**
     * @brief Return a terminal protocol-error step.
     *
     * @return Denied protocol result.
     */
    step_t protocol_error() {
      return {step_t::state_e::denied, {}, phase_e::protocol, -1};
    }

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

  pam_client_t::~pam_client_t() {
    close();
  }

  pam_client_t::pam_client_t(pam_client_t &&other) noexcept:
      descriptor_ {std::exchange(other.descriptor_, -1)},
      transaction_id_ {std::exchange(other.transaction_id_, 0)},
      expected_responses_ {std::exchange(other.expected_responses_, 0)},
      operation_timeout_ {other.operation_timeout_},
      cancellation_ {std::move(other.cancellation_)} {
  }

  pam_client_t &pam_client_t::operator=(pam_client_t &&other) noexcept {
    if (this != &other) {
      close();
      descriptor_ = std::exchange(other.descriptor_, -1);
      transaction_id_ = std::exchange(other.transaction_id_, 0);
      expected_responses_ = std::exchange(other.expected_responses_, 0);
      operation_timeout_ = other.operation_timeout_;
      cancellation_ = std::move(other.cancellation_);
    }
    return *this;
  }

  step_t pam_client_t::begin(std::uint64_t transaction_id, std::string_view username, std::string_view remote_host, std::string_view tty) {
    close();
    const io_context_t context {io_context_t::clock_t::now() + operation_timeout_, cancellation_.get_token()};
    if (transaction_id == 0 || username.empty() || username.size() > 256 || remote_host.size() > 256 || tty.size() > 128) {
      return protocol_error();
    }
    descriptor_ = broker_channel::request_connection(context);
    if (descriptor_ < 0) {
      return protocol_error();
    }
    transaction_id_ = transaction_id;
    std::vector<std::uint8_t> payload;
    if (!append_string(payload, username) || !append_string(payload, remote_host) || !append_string(payload, tty) || !write_message(descriptor_, {message_type_e::begin, transaction_id_, std::move(payload)}, context)) {
      close();
      return protocol_error();
    }
    return read_step(context);
  }

  step_t pam_client_t::respond(std::vector<std::string> responses) {
    const io_context_t context {io_context_t::clock_t::now() + operation_timeout_, cancellation_.get_token()};
    if (descriptor_ < 0 || expected_responses_ == 0 || responses.size() != expected_responses_) {
      erase(responses);
      close();
      return protocol_error();
    }
    std::vector<std::uint8_t> payload;
    append_integer(payload, static_cast<std::uint32_t>(responses.size()));
    bool valid = true;
    for (const auto &response : responses) {
      valid = valid && append_string(payload, response);
    }
    erase(responses);
    expected_responses_ = 0;
    const bool written = valid && write_sensitive_message(descriptor_, {
                                                                         message_type_e::response,
                                                                         transaction_id_,
                                                                         payload,
                                                                       },
                                                          context);
    if (!payload.empty()) {
      explicit_bzero(payload.data(), payload.size());
    }
    if (!written) {
      close();
      return protocol_error();
    }
    return read_step(context);
  }

  void pam_client_t::close() {
    if (descriptor_ >= 0) {
      // EOF already closes the broker's PAM session. Never wait for a cancel
      // write (or a PAM cleanup reply) during token destruction/shutdown.
      shutdown(descriptor_, SHUT_RDWR);
      ::close(descriptor_);
    }
    descriptor_ = -1;
    transaction_id_ = 0;
    expected_responses_ = 0;
  }

  void pam_client_t::cancel() noexcept {
    cancellation_.request_stop();
  }

  bool pam_client_t::connected() const {
    return descriptor_ >= 0;
  }

#ifdef SUNSHINE_TESTS
  pam_client_t pam_client_t::adopt_for_test(int descriptor, std::uint64_t transaction_id, std::chrono::milliseconds timeout) {
    pam_client_t client {timeout};
    client.descriptor_ = descriptor;
    client.transaction_id_ = transaction_id;
    return client;
  }

  step_t pam_client_t::read_step_for_test() {
    return read_step({io_context_t::clock_t::now() + operation_timeout_, cancellation_.get_token()});
  }
#endif

  step_t pam_client_t::read_step(const io_context_t &context) {
    message_t message;
    if (!read_message(descriptor_, message, context) || message.transaction_id != transaction_id_) {
      close();
      return protocol_error();
    }
    if (message.type == message_type_e::challenge) {
      std::size_t offset = 0;
      std::uint32_t count;
      if (!read_integer(message.payload, offset, count) || count == 0 || count > maximum_fields) {
        close();
        return protocol_error();
      }
      step_t step {step_t::state_e::challenge, {}};
      step.prompts.reserve(count);
      for (std::uint32_t index = 0; index < count; ++index) {
        std::int32_t style;
        std::string text;
        if (!read_integer(message.payload, offset, style) || !read_string(message.payload, offset, text)) {
          close();
          return protocol_error();
        }
        step.prompts.push_back({style, std::move(text)});
      }
      if (offset != message.payload.size()) {
        close();
        return protocol_error();
      }
      expected_responses_ = count;
      return step;
    }
    if (message.type == message_type_e::result) {
      std::size_t offset = 0;
      std::uint16_t phase;
      std::int32_t pam_status;
      if (!read_integer(message.payload, offset, phase) || !read_integer(message.payload, offset, pam_status) || offset != message.payload.size() || phase < static_cast<std::uint16_t>(phase_e::protocol) || phase > static_cast<std::uint16_t>(phase_e::authenticated)) {
        close();
        return protocol_error();
      }
      const bool success = phase == static_cast<std::uint16_t>(phase_e::authenticated) &&
                           pam_status == 0;
      if (!success) {
        close();
      }
      return {
        success ? step_t::state_e::authenticated : step_t::state_e::denied,
        {},
        static_cast<phase_e>(phase),
        pam_status,
      };
    }
    close();
    return protocol_error();
  }
}  // namespace plank::auth
