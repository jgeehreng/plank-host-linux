/**
 * @file src/auth/pam_broker.cpp
 * @brief Privileged PLANK PAM conversation broker.
 */

#include "pam_broker_policy.h"
#include "pam_broker_protocol.h"
#include "pam_worker_watch.h"

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <memory>
#include <security/pam_appl.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace auth = plank::auth;

namespace {
  constexpr std::string_view default_socket_path = "/run/plank/pam/auth.sock";
  constexpr std::string_view default_config_path = "/etc/plank/host.conf";
  constexpr std::string_view pam_service = "plank-host";

  volatile std::sig_atomic_t stopping = 0;  ///< Set by termination signals.
  volatile std::sig_atomic_t listening_descriptor = -1;  ///< Listener closed by the signal handler.
  auth::pam_workers_t children;  ///< Active workers and caller-disconnect cleanup watches.

  /**
   * @brief Own and close a POSIX file descriptor.
   */
  class descriptor_t {
  public:
    /**
     * @brief Construct an optional descriptor owner.
     *
     * @param value Descriptor to own, or `-1`.
     */
    explicit descriptor_t(int value = -1):
        value_ {value} {
    }

    /**
     * @brief Close the owned descriptor.
     */
    ~descriptor_t() {
      if (value_ >= 0) {
        close(value_);
      }
    }

    descriptor_t(const descriptor_t &) = delete;
    descriptor_t &operator=(const descriptor_t &) = delete;

    /**
     * @brief Return the owned descriptor.
     *
     * @return Descriptor value.
     */
    int get() const {
      return value_;
    }

    /**
     * @brief Release ownership without closing.
     *
     * @return Previously owned descriptor.
     */
    int release() {
      return std::exchange(value_, -1);
    }

  private:
    int value_;  ///< Owned descriptor.
  };

  /**
   * @brief State supplied to the synchronous PAM conversation callback.
   */
  struct conversation_t {
    int descriptor;  ///< Connected unprivileged broker client.
    std::uint64_t transaction_id;  ///< Active transaction identifier.
  };

  /**
   * @brief Securely erase all response strings.
   *
   * @param responses Response strings to erase.
   */
  void erase_responses(std::vector<std::string> &responses) {
    for (auto &response : responses) {
      if (!response.empty()) {
        explicit_bzero(response.data(), response.size());
      }
    }
  }

  /**
   * @brief Encode a PAM challenge payload.
   *
   * @param messages PAM messages supplied to the callback.
   * @param message_count Number of messages.
   * @param payload Receives the bounded payload.
   * @return True when every message was valid.
   */
  bool encode_challenge(const pam_message **messages, int message_count, std::vector<std::uint8_t> &payload) {
    if (messages == nullptr || message_count <= 0 || message_count > static_cast<int>(auth::maximum_fields)) {
      return false;
    }
    auth::append_integer(payload, static_cast<std::uint32_t>(message_count));
    for (int index = 0; index < message_count; ++index) {
      if (messages[index] == nullptr || messages[index]->msg == nullptr) {
        return false;
      }
      const int style = messages[index]->msg_style;
      if (style != PAM_PROMPT_ECHO_ON && style != PAM_PROMPT_ECHO_OFF && style != PAM_TEXT_INFO && style != PAM_ERROR_MSG) {
        return false;
      }
      auth::append_integer(payload, static_cast<std::int32_t>(style));
      if (!auth::append_string(payload, messages[index]->msg)) {
        return false;
      }
    }
    return true;
  }

  /**
   * @brief Decode response strings returned by Sunshine.
   *
   * @param payload Encoded response payload.
   * @param expected_count Required number of entries.
   * @param responses Receives decoded strings.
   * @return True when the payload was exact and bounded.
   */
  bool decode_responses(std::span<const std::uint8_t> payload, int expected_count, std::vector<std::string> &responses) {
    std::size_t offset = 0;
    std::uint32_t count;
    if (!auth::read_integer(payload, offset, count) || count != static_cast<std::uint32_t>(expected_count) || count > auth::maximum_fields) {
      return false;
    }
    responses.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
      std::string response;
      if (!auth::read_string(payload, offset, response)) {
        erase_responses(responses);
        return false;
      }
      responses.push_back(std::move(response));
    }
    return offset == payload.size();
  }

  /**
   * @brief Bridge one PAM conversation to the unprivileged caller.
   *
   * @param message_count PAM message count.
   * @param messages PAM message array.
   * @param responses Receives allocated PAM responses.
   * @param application_data A @ref conversation_t pointer.
   * @return A PAM status code.
   */
  int converse(int message_count, const pam_message **messages, pam_response **responses, void *application_data) {
    if (responses == nullptr || application_data == nullptr) {
      return PAM_CONV_ERR;
    }
    auto &conversation = *static_cast<conversation_t *>(application_data);
    std::vector<std::uint8_t> challenge_payload;
    if (!encode_challenge(messages, message_count, challenge_payload) || !auth::write_message(conversation.descriptor, {
                                                                                                                         auth::message_type_e::challenge,
                                                                                                                         conversation.transaction_id,
                                                                                                                         std::move(challenge_payload),
                                                                                                                       })) {
      return PAM_CONV_ERR;
    }

    auth::message_t reply;
    const auth::io_context_t human_response {auth::io_context_t::clock_t::now() + std::chrono::seconds {120}, {}};
    if (!auth::read_message(conversation.descriptor, reply, human_response) || reply.type != auth::message_type_e::response || reply.transaction_id != conversation.transaction_id) {
      return PAM_CONV_ERR;
    }
    std::vector<std::string> decoded;
    const bool decoded_responses = decode_responses(reply.payload, message_count, decoded);
    if (!reply.payload.empty()) {
      explicit_bzero(reply.payload.data(), reply.payload.size());
    }
    if (!decoded_responses) {
      return PAM_CONV_ERR;
    }

    auto allocated = static_cast<pam_response *>(
      calloc(static_cast<std::size_t>(message_count), sizeof(pam_response))
    );
    if (allocated == nullptr) {
      erase_responses(decoded);
      return PAM_BUF_ERR;
    }
    for (int index = 0; index < message_count; ++index) {
      const int style = messages[index]->msg_style;
      if (style == PAM_PROMPT_ECHO_ON || style == PAM_PROMPT_ECHO_OFF) {
        allocated[index].resp = strdup(decoded[index].c_str());
        if (allocated[index].resp == nullptr) {
          for (int previous = 0; previous < index; ++previous) {
            if (allocated[previous].resp != nullptr) {
              explicit_bzero(allocated[previous].resp, std::strlen(allocated[previous].resp));
              free(allocated[previous].resp);
            }
          }
          free(allocated);
          erase_responses(decoded);
          return PAM_BUF_ERR;
        }
      } else if (style != PAM_TEXT_INFO && style != PAM_ERROR_MSG) {
        free(allocated);
        erase_responses(decoded);
        return PAM_CONV_ERR;
      }
    }
    erase_responses(decoded);
    *responses = allocated;
    return PAM_SUCCESS;
  }

  /**
   * @brief Send a PAM operation result.
   *
   * @param descriptor Connected caller.
   * @param transaction_id Active transaction.
   * @param phase Operation that produced the result.
   * @param pam_status PAM status code.
   * @return True when the result was sent.
   */
  bool send_result(int descriptor, std::uint64_t transaction_id, auth::phase_e phase, int pam_status) {
    std::vector<std::uint8_t> payload;
    auth::append_integer(payload, static_cast<std::uint16_t>(phase));
    auth::append_integer(payload, static_cast<std::int32_t>(pam_status));
    return auth::write_message(descriptor, {
                                             auth::message_type_e::result,
                                             transaction_id,
                                             std::move(payload),
                                           });
  }

  /**
   * @brief Parse the username, remote host, and logical TTY from a begin request.
   *
   * @param payload Begin payload.
   * @param username Receives the account name.
   * @param remote_host Receives the source host label.
   * @param tty Receives the logical service terminal.
   * @return True when exactly three valid fields were supplied.
   */
  bool decode_begin(std::span<const std::uint8_t> payload, std::string &username, std::string &remote_host, std::string &tty) {
    std::size_t offset = 0;
    return auth::read_string(payload, offset, username) && !username.empty() &&
           username.size() <= 256 && auth::read_string(payload, offset, remote_host) &&
           remote_host.size() <= 256 && auth::read_string(payload, offset, tty) &&
           tty.size() <= 128 && offset == payload.size();
  }

  /**
   * @brief Invoke one PAM operation and send its failure result.
   *
   * @tparam Operation Callable returning a PAM status.
   * @param descriptor Connected caller.
   * @param transaction_id Active transaction.
   * @param phase Operation phase.
   * @param operation PAM call.
   * @return PAM status.
   */
  template<typename Operation>
  int run_phase(int descriptor, std::uint64_t transaction_id, auth::phase_e phase, Operation operation) {
    const int status = operation();
    if (status != PAM_SUCCESS) {
      send_result(descriptor, transaction_id, phase, status);
    }
    return status;
  }

  /**
   * @brief Authenticate one caller and retain its PAM session until disconnect.
   *
   * @param descriptor Connected Unix socket.
   * @param peer_uid Authenticated local peer UID.
   */
  void serve_client(int descriptor, uid_t peer_uid, bool allow_root_login) {
    descriptor_t connection {descriptor};
    auth::message_t begin;
    if (!auth::read_message(connection.get(), begin) || begin.type != auth::message_type_e::begin) {
      return;
    }

    std::string username;
    std::string remote_host;
    std::string tty;
    if (!decode_begin(begin.payload, username, remote_host, tty)) {
      send_result(connection.get(), begin.transaction_id, auth::phase_e::protocol, PAM_SYSTEM_ERR);
      return;
    }
    if (username == "root" && !allow_root_login) {
      send_result(connection.get(), begin.transaction_id, auth::phase_e::account, PAM_PERM_DENIED);
      std::clog << "PLANK PAM denied root request from uid " << peer_uid << '\n';
      return;
    }

    conversation_t state {connection.get(), begin.transaction_id};
    const pam_conv callback {converse, &state};
    pam_handle_t *handle = nullptr;
    int status = pam_start(pam_service.data(), username.c_str(), &callback, &handle);
    if (status != PAM_SUCCESS) {
      send_result(connection.get(), begin.transaction_id, auth::phase_e::start, status);
      return;
    }

    bool credentials_established = false;
    bool session_open = false;
    if (pam_set_item(handle, PAM_RHOST, remote_host.c_str()) != PAM_SUCCESS || pam_set_item(handle, PAM_TTY, tty.c_str()) != PAM_SUCCESS) {
      status = PAM_SYSTEM_ERR;
      send_result(connection.get(), begin.transaction_id, auth::phase_e::start, status);
    } else {
      status = run_phase(connection.get(), begin.transaction_id, auth::phase_e::authenticate, [&]() {
        return pam_authenticate(handle, 0);
      });
    }
    if (status == PAM_SUCCESS) {
      status = run_phase(connection.get(), begin.transaction_id, auth::phase_e::account, [&]() {
        return pam_acct_mgmt(handle, 0);
      });
    }
    if (status == PAM_SUCCESS) {
      status = run_phase(connection.get(), begin.transaction_id, auth::phase_e::establish_credentials, [&]() {
        return pam_setcred(handle, PAM_ESTABLISH_CRED);
      });
      credentials_established = status == PAM_SUCCESS;
    }
    if (status == PAM_SUCCESS) {
      status = run_phase(connection.get(), begin.transaction_id, auth::phase_e::open_session, [&]() {
        return pam_open_session(handle, 0);
      });
      session_open = status == PAM_SUCCESS;
    }
    if (status == PAM_SUCCESS) {
      const bool delivered = send_result(connection.get(), begin.transaction_id, auth::phase_e::authenticated, PAM_SUCCESS);
      std::clog << "PLANK PAM authenticated account " << username
                << " for local uid " << peer_uid << '\n';
      auth::message_t cancel;
      const auth::io_context_t session_lifetime {auth::io_context_t::clock_t::time_point::max(), {}};
      if (delivered && auth::read_message(connection.get(), cancel, session_lifetime) && (cancel.type != auth::message_type_e::cancel || cancel.transaction_id != begin.transaction_id)) {
        std::clog << "PLANK PAM received invalid session-close message\n";
      }
    } else {
      std::clog << "PLANK PAM denied account " << username
                << " for local uid " << peer_uid << " with status " << status << '\n';
    }

    if (session_open) {
      pam_close_session(handle, 0);
    }
    if (credentials_established) {
      pam_setcred(handle, PAM_DELETE_CRED);
    }
    pam_end(handle, status);
  }

  /**
   * @brief Create the broker Unix listener with restrictive ownership.
   *
   * @param path Socket filesystem path.
   * @return Listening descriptor, or `-1` on error.
   */
  int create_listener(const std::filesystem::path &path) {
    const auto parent = path.parent_path();
    if (!path.is_absolute() || path.filename().empty() || parent.filename().empty() || parent.parent_path().filename().empty() || path.string().size() >= sizeof(sockaddr_un::sun_path)) {
      std::cerr << "PAM broker socket must use a dedicated absolute runtime directory\n";
      return -1;
    }
    std::error_code error;
    const auto existing_parent = std::filesystem::symlink_status(parent, error);
    if (!error && (std::filesystem::is_symlink(existing_parent) || !std::filesystem::is_directory(existing_parent))) {
      std::cerr << "PAM broker runtime path is not a real directory\n";
      return -1;
    }
    error.clear();
    std::filesystem::create_directory(path.parent_path(), error);
    if (error) {
      std::cerr << "Unable to create PAM broker runtime directory: " << error.message() << '\n';
      return -1;
    }
    struct stat parent_metadata {};
    if (lstat(parent.c_str(), &parent_metadata) < 0 || !S_ISDIR(parent_metadata.st_mode) || parent_metadata.st_uid != 0) {
      std::cerr << "PAM broker runtime directory must be owned by root\n";
      return -1;
    }
    if (chown(path.parent_path().c_str(), 0, 0) < 0 || chmod(path.parent_path().c_str(), 0700) < 0) {
      std::cerr << "Unable to secure PAM broker runtime directory: "
                << std::strerror(errno) << '\n';
      return -1;
    }
    struct stat existing_socket {};
    if (lstat(path.c_str(), &existing_socket) == 0) {
      if (!S_ISSOCK(existing_socket.st_mode) || existing_socket.st_uid != 0) {
        std::cerr << "Refusing to replace unsafe PAM broker socket path\n";
        return -1;
      }
      if (unlink(path.c_str()) < 0) {
        std::cerr << "Unable to replace stale PAM broker socket: "
                  << std::strerror(errno) << '\n';
        return -1;
      }
    } else if (errno != ENOENT) {
      std::cerr << "Unable to inspect PAM broker socket path: "
                << std::strerror(errno) << '\n';
      return -1;
    }

    descriptor_t listener {socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    if (listener.get() < 0) {
      std::cerr << "Unable to create PAM broker socket: " << std::strerror(errno) << '\n';
      return -1;
    }
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.string().size() + 1);
    if (bind(listener.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)) < 0 || chown(path.c_str(), 0, 0) < 0 || chmod(path.c_str(), 0600) < 0 || listen(listener.get(), 16) < 0) {
      std::cerr << "Unable to bind PAM broker socket: " << std::strerror(errno) << '\n';
      unlink(path.c_str());
      return -1;
    }
    return listener.release();
  }

  /**
   * @brief Stop accepting new broker clients.
   *
   * @param signal_number Delivered signal number.
   */
  void stop(int signal_number) {
    (void) signal_number;
    stopping = 1;
    const int descriptor = listening_descriptor;
    listening_descriptor = -1;
    if (descriptor >= 0) {
      close(descriptor);
    }
  }

  /**
   * @brief Print command-line syntax.
   *
   * @param program Program path.
   */
  void usage(const char *program) {
    std::cerr << "usage: " << program
              << " [--socket PATH] [--config PATH] [--check-config]\n";
  }
}  // namespace

/**
 * @brief Run the PLANK PAM broker.
 *
 * @param argc Argument count.
 * @param argv Argument values.
 * @return Process exit status.
 */
int main(int argc, char **argv) {
  std::filesystem::path socket_path {default_socket_path};
  std::string config_path {default_config_path};
  bool check_config = false;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument {argv[index]};
    if (argument == "--socket" && index + 1 < argc) {
      socket_path = argv[++index];
    } else if (argument == "--config" && index + 1 < argc) {
      config_path = argv[++index];
    } else if (argument == "--check-config") {
      check_config = true;
    } else {
      usage(argv[0]);
      return 2;
    }
  }
  if (geteuid() != 0) {
    std::cerr << "plank-pam-broker must run as root\n";
    return 3;
  }

  std::string policy_error;
  const auto policy = auth::load_broker_policy(config_path, policy_error);
  if (!policy) {
    std::cerr << "Unable to load PAM broker policy: " << policy_error << '\n';
    return 4;
  }
  if (check_config) {
    std::cout << "allow_root_login="
              << (policy->allow_root_login ? "true" : "false") << '\n';
    return 0;
  }

  const int listener = create_listener(socket_path);
  if (listener < 0) {
    return 5;
  }
  listening_descriptor = listener;
  std::signal(SIGINT, stop);
  std::signal(SIGTERM, stop);
  std::signal(SIGCHLD, SIG_DFL);  // Preserve waitpid ownership even if the launcher ignored SIGCHLD.
  std::clog << "PLANK PAM broker listening on " << socket_path
            << "; root login " << (policy->allow_root_login ? "allowed" : "denied") << '\n';

  while (!stopping) {
    if (children.maintain() != 0) {
      std::clog << "PLANK PAM terminated stalled worker after caller disconnect\n";
    }
    // Periodically observe caller EOF even when a PAM module never returns.
    // This also avoids missing SIGCHLD between reaping and a blocking accept.
    pollfd ready {listener, POLLIN, 0};
    if (poll(&ready, 1, 100) <= 0) {
      continue;
    }
    if (stopping) {
      break;
    }
    sockaddr_un peer_address {};
    socklen_t peer_length = sizeof(peer_address);
    const int client = accept4(listener, reinterpret_cast<sockaddr *>(&peer_address), &peer_length, SOCK_CLOEXEC);
    if (client < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (!stopping) {
        std::cerr << "PAM broker accept failed: " << std::strerror(errno) << '\n';
      }
      break;
    }

    ucred credentials {};
    socklen_t credentials_length = sizeof(credentials);
    if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &credentials, &credentials_length) < 0 || credentials_length != sizeof(credentials) || credentials.uid != 0) {
      close(client);
      continue;
    }
    if (children.size() >= 32) {
      close(client);
      continue;
    }

    const pid_t child = fork();
    if (child == 0) {
      close(listener);
      children.close_in_child();
      std::signal(SIGINT, SIG_DFL);
      std::signal(SIGTERM, SIG_DFL);
      serve_client(client, credentials.uid, policy->allow_root_login);
      std::_Exit(0);
    }

    if (child > 0) {
      children.add(child, client);
    } else {
      close(client);
      std::cerr << "Unable to fork PAM broker worker: " << std::strerror(errno) << '\n';
    }
  }

  const int descriptor = listening_descriptor;
  listening_descriptor = -1;
  if (descriptor >= 0) {
    close(descriptor);
  }
  children.maintain();
  children.stop();
  unlink(socket_path.c_str());
  return 0;
}
