/**
 * @file src/session/gdm_login_helper.cpp
 * @brief Privileged GDM UserVerifier helper for post-PAM desktop start.
 */
#include "gdm_login.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>
#include <unistd.h>
#include <string.h>

using namespace std::literals;

namespace {
  constexpr std::string_view gdm_account = "gdm";
  constexpr std::string_view gdm_service = "gdm-password";
  constexpr std::string_view session_path = "/org/gnome/DisplayManager/Session";
  constexpr std::string_view verifier_interface = "org.gnome.DisplayManager.UserVerifier";
  constexpr std::string_view greeter_interface = "org.gnome.DisplayManager.Greeter";
  constexpr auto gdm_timeout = std::chrono::seconds {20};
  constexpr auto gdm_parent_wait = gdm_timeout + std::chrono::seconds {5};
  constexpr std::size_t maximum_payload = 4096;

  volatile std::sig_atomic_t stopping = 0;
  volatile std::sig_atomic_t listening_descriptor = -1;

  using step_t = plank::session::gdm_login_step;

  /**
   * @brief Wipe secret strings.
   *
   * @param secrets Values to erase.
   */
  void wipe(std::vector<std::string> &secrets) {
    for (auto &secret : secrets) {
      if (!secret.empty()) {
        explicit_bzero(secret.data(), secret.size());
      }
    }
    secrets.clear();
  }

  /**
   * @brief Wipe one heap string.
   *
   * @param value Value to erase.
   */
  void wipe_string(std::string &value) {
    if (!value.empty()) {
      explicit_bzero(value.data(), value.size());
      value.clear();
    }
  }

  /**
   * @brief Resolve the local GDM greeter account.
   *
   * @return Greeter UID and GID, or no value when NSS has no `gdm` user.
   */
  std::optional<std::pair<uid_t, gid_t>> gdm_account_ids() {
    constexpr std::size_t maximum_buffer = 1024U * 1024U;
    std::size_t size = 16384;
    std::vector<char> buffer(size);
    passwd record {};
    passwd *result = nullptr;
    while (true) {
      const int status = getpwnam_r(
        gdm_account.data(),
        &record,
        buffer.data(),
        buffer.size(),
        &result
      );
      if (status == 0 && result != nullptr && result->pw_uid != 0) {
        return std::pair<uid_t, gid_t> {result->pw_uid, result->pw_gid};
      }
      if (status != ERANGE || buffer.size() >= maximum_buffer) {
        return std::nullopt;
      }
      buffer.resize(std::min(buffer.size() * 2, maximum_buffer));
    }
  }

  /**
   * @brief Join the greeter logind session so GDM OpenSession maps this process to seat0.
   *
   * @param session_id Active greeter session.
   * @return True when this process was moved into the session cgroup.
   */
  bool join_session_cgroup(std::string_view session_id) {
    if (session_id.empty()) {
      return false;
    }
    std::error_code error;
    for (const auto &entry : std::filesystem::directory_iterator("/proc", error)) {
      if (!entry.is_directory(error)) {
        continue;
      }
      const auto name = entry.path().filename().string();
      pid_t pid {};
      const auto parsed = std::from_chars(name.data(), name.data() + name.size(), pid);
      if (parsed.ec != std::errc {} || parsed.ptr != name.data() + name.size() || pid <= 0) {
        continue;
      }
      char *raw_session = nullptr;
      if (sd_pid_get_session(pid, &raw_session) < 0 || raw_session == nullptr) {
        continue;
      }
      const std::unique_ptr<char, decltype(&free)> session {raw_session, &free};
      if (session_id != session.get()) {
        continue;
      }
      char *raw_cgroup = nullptr;
      if (sd_pid_get_cgroup(pid, &raw_cgroup) < 0 || raw_cgroup == nullptr) {
        continue;
      }
      const std::unique_ptr<char, decltype(&free)> cgroup {raw_cgroup, &free};
      std::string procs = "/sys/fs/cgroup";
      if (cgroup.get()[0] != '/') {
        procs.push_back('/');
      }
      procs.append(cgroup.get());
      procs.append("/cgroup.procs");
      const int descriptor = open(procs.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
      if (descriptor < 0) {
        continue;
      }
      const auto text = std::to_string(getpid());
      const auto wrote = write(descriptor, text.data(), text.size());
      close(descriptor);
      if (wrote == static_cast<ssize_t>(text.size())) {
        return true;
      }
    }
    return false;
  }

  /**
   * @brief Drop to the GDM greeter identity.
   *
   * @param ids Greeter UID and GID.
   * @return True when credentials were applied.
   */
  bool become_gdm(std::pair<uid_t, gid_t> ids) {
    if (setgid(ids.second) != 0) {
      return false;
    }
    if (initgroups(gdm_account.data(), ids.second) != 0) {
      return false;
    }
    if (setuid(ids.first) != 0 || geteuid() != ids.first) {
      return false;
    }
    const auto runtime = "/run/user/" + std::to_string(ids.first);
    return setenv("XDG_RUNTIME_DIR", runtime.c_str(), 1) == 0 &&
           setenv("XDG_SESSION_CLASS", "greeter", 1) == 0 &&
           setenv("XDG_SESSION_TYPE", "x11", 1) == 0;
  }

  /**
   * @brief Open GDM's private greeter peer connection.
   *
   * GDM 40 OpenSession returns the existing display's GDBusServer address.
   * That is a peer socket, not a message bus. Hello as a bus client fails
   * after gnome-shell already holds the same server.
   *
   * @param bus Destination for the started connection.
   * @param step Set to open_session_failed or connect_failed on error.
   * @return True when the helper is on the greeter UserVerifier connection.
   */
  bool open_gdm_session(sd_bus **bus, step_t &step) {
    sd_bus *system_bus = nullptr;
    if (sd_bus_open_system(&system_bus) < 0 || system_bus == nullptr) {
      step = step_t::open_session_failed;
      std::fprintf(stderr, "GDM OpenSession failed: system bus unavailable\n");
      std::fflush(stderr);
      return false;
    }
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = nullptr;
    const int status = sd_bus_call_method(
      system_bus,
      "org.gnome.DisplayManager",
      "/org/gnome/DisplayManager/Manager",
      "org.gnome.DisplayManager.Manager",
      "OpenSession",
      &error,
      &reply,
      nullptr
    );
    const char *address = nullptr;
    if (status >= 0 && reply != nullptr) {
      sd_bus_message_read(reply, "s", &address);
    }
    if (status < 0 || address == nullptr || address[0] == '\0') {
      step = step_t::open_session_failed;
      if (sd_bus_error_is_set(&error)) {
        std::fprintf(stderr, "GDM OpenSession failed: %s\n", error.message);
      } else {
        std::fprintf(stderr, "GDM OpenSession failed: empty address\n");
      }
      std::fflush(stderr);
      sd_bus_error_free(&error);
      sd_bus_message_unref(reply);
      sd_bus_unref(system_bus);
      return false;
    }
    std::string peer_address {address};
    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    sd_bus_unref(system_bus);

    sd_bus *private_bus = nullptr;
    const int opened = sd_bus_new(&private_bus);
    const int addressed = opened >= 0 ? sd_bus_set_address(private_bus, peer_address.c_str()) : opened;
    // Peer GDBusServer: do not send a message-bus Hello.
    const int peer = addressed >= 0 ? sd_bus_set_bus_client(private_bus, 0) : addressed;
    const int started = peer >= 0 ? sd_bus_start(private_bus) : peer;
    if (started < 0 || private_bus == nullptr) {
      step = step_t::connect_failed;
      std::fprintf(
        stderr,
        "GDM private session connect failed: %s\n",
        strerror(-started)
      );
      std::fflush(stderr);
      sd_bus_unref(private_bus);
      return false;
    }
    *bus = private_bus;
    return true;
  }

  /**
   * @brief Take the next unused PAM secret out of the list.
   *
   * @param secrets Remaining secrets.
   * @return The next secret, or empty when none remain.
   */
  std::string take_secret(std::vector<std::string> &secrets) {
    for (auto &secret : secrets) {
      if (!secret.empty()) {
        std::string value = std::move(secret);
        secret.clear();
        return value;
      }
    }
    return {};
  }

  /**
   * @brief Mutable GDM UserVerifier conversation.
   */
  struct verifier_state_t {
    sd_bus *bus = nullptr;  ///< Private GDM session bus.
    std::string username;  ///< PAM account used for echo-on queries.
    std::vector<std::string> *secrets = nullptr;  ///< Remaining PAM responses.
    bool complete = false;  ///< VerificationComplete received.
    bool failed = false;  ///< GDM reported a problem or a secret was missing.
  };

  /**
   * @brief Answer one UserVerifier signal.
   *
   * @param message Signal from GDM.
   * @param userdata Conversation state.
   * @return 0 to keep the match.
   */
  int handle_verifier_signal(sd_bus_message *message, void *userdata, sd_bus_error *) {
    auto *state = static_cast<verifier_state_t *>(userdata);
    if (state == nullptr || state->bus == nullptr || message == nullptr) {
      return 0;
    }
    const char *member = sd_bus_message_get_member(message);
    if (member == nullptr) {
      return 0;
    }
    if (std::strcmp(member, "VerificationComplete") == 0) {
      state->complete = true;
      return 0;
    }
    if (std::strcmp(member, "VerificationFailed") == 0 ||
        std::strcmp(member, "Problem") == 0 ||
        std::strcmp(member, "ServiceUnavailable") == 0) {
      state->failed = true;
      return 0;
    }

    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = nullptr;
    int status = 0;
    if (std::strcmp(member, "SecretInfoQuery") == 0) {
      std::string secret = state->secrets != nullptr ? take_secret(*state->secrets) : std::string {};
      if (secret.empty()) {
        wipe_string(secret);
        state->failed = true;
        return 0;
      }
      status = sd_bus_call_method(
        state->bus,
        nullptr,
        session_path.data(),
        verifier_interface.data(),
        "AnswerQuery",
        &error,
        &reply,
        "ss",
        gdm_service.data(),
        secret.c_str()
      );
      wipe_string(secret);
    } else if (std::strcmp(member, "InfoQuery") == 0) {
      status = sd_bus_call_method(
        state->bus,
        nullptr,
        session_path.data(),
        verifier_interface.data(),
        "AnswerQuery",
        &error,
        &reply,
        "ss",
        gdm_service.data(),
        state->username.c_str()
      );
    }
    sd_bus_message_unref(reply);
    sd_bus_error_free(&error);
    if (status < 0) {
      state->failed = true;
    }
    return 0;
  }

  /**
   * @brief Run the GDM UserVerifier conversation.
   *
   * @param username PAM account.
   * @param secrets PAM responses.
   * @return Which GDM step finished the conversation.
   */
  step_t verify_and_start(std::string_view username, std::vector<std::string> &secrets) {
    sd_bus *bus = nullptr;
    step_t open_step = step_t::open_session_failed;
    if (!open_gdm_session(&bus, open_step) || bus == nullptr) {
      return open_step;
    }
    const std::unique_ptr<sd_bus, decltype(&sd_bus_unref)> hold {bus, &sd_bus_unref};
    verifier_state_t state {
      bus,
      std::string {username},
      &secrets,
      false,
      false
    };
    if (sd_bus_match_signal(
          bus,
          nullptr,
          nullptr,
          nullptr,
          verifier_interface.data(),
          nullptr,
          handle_verifier_signal,
          &state
        ) < 0) {
      std::fprintf(stderr, "GDM UserVerifier signal match failed\n");
      std::fflush(stderr);
      return step_t::connect_failed;
    }

    // Drop an idle greeter conversation so this helper owns UserVerifier.
    sd_bus_call_method(
      bus,
      nullptr,
      session_path.data(),
      verifier_interface.data(),
      "Cancel",
      nullptr,
      nullptr,
      nullptr
    );

    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = nullptr;
    int status = sd_bus_call_method(
      bus,
      nullptr,
      session_path.data(),
      verifier_interface.data(),
      "BeginVerificationForUser",
      &error,
      &reply,
      "ss",
      gdm_service.data(),
      state.username.c_str()
    );
    sd_bus_message_unref(reply);
    reply = nullptr;
    if (status < 0) {
      if (sd_bus_error_is_set(&error)) {
        std::fprintf(stderr, "GDM BeginVerificationForUser failed: %s\n", error.message);
        std::fflush(stderr);
      }
      sd_bus_error_free(&error);
      return step_t::begin_failed;
    }
    sd_bus_error_free(&error);

    const auto deadline = std::chrono::steady_clock::now() + gdm_timeout;
    while (!state.complete && !state.failed) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        sd_bus_call_method(
          bus,
          nullptr,
          session_path.data(),
          verifier_interface.data(),
          "Cancel",
          nullptr,
          nullptr,
          nullptr
        );
        return step_t::verify_timeout;
      }
      const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
      if (sd_bus_wait(bus, static_cast<uint64_t>(remaining.count())) < 0) {
        return step_t::verify_failed;
      }
      while (sd_bus_process(bus, nullptr) > 0) {
      }
    }
    if (!state.complete) {
      return step_t::verify_failed;
    }

    error = SD_BUS_ERROR_NULL;
    reply = nullptr;
    status = sd_bus_call_method(
      bus,
      nullptr,
      session_path.data(),
      greeter_interface.data(),
      "StartSessionWhenReady",
      &error,
      &reply,
      "sb",
      gdm_service.data(),
      1
    );
    if (status < 0 && sd_bus_error_is_set(&error)) {
      std::fprintf(stderr, "GDM StartSessionWhenReady failed: %s\n", error.message);
      std::fflush(stderr);
    }
    sd_bus_message_unref(reply);
    sd_bus_error_free(&error);
    return status >= 0 ? step_t::ok : step_t::start_failed;
  }

  /**
   * @brief Child entry: join the greeter session, drop to gdm, and start the desktop.
   *
   * @param username PAM account.
   * @param secrets PAM responses.
   * @param greeter_session Active greeter logind session.
   * @return Encoded start result for the parent.
   */
  unsigned char run_as_gdm(
    std::string username,
    std::vector<std::string> secrets,
    std::string greeter_session
  ) {
    const auto ids = gdm_account_ids();
    if (!ids) {
      wipe(secrets);
      return static_cast<unsigned char>(step_t::no_gdm_account);
    }
    if (!join_session_cgroup(greeter_session) || !become_gdm(*ids)) {
      wipe(secrets);
      return static_cast<unsigned char>(step_t::join_failed);
    }
    const auto started = verify_and_start(username, secrets);
    wipe(secrets);
    wipe_string(username);
    return static_cast<unsigned char>(started);
  }

  /**
   * @brief Read an entire buffer.
   *
   * @param descriptor Client socket.
   * @param data Destination.
   * @param size Byte count.
   * @return True when every byte was read.
   */
  bool read_fully(int descriptor, void *data, std::size_t size) {
    auto *bytes = static_cast<std::uint8_t *>(data);
    std::size_t offset = 0;
    while (offset < size) {
      const auto got = read(descriptor, bytes + offset, size - offset);
      if (got < 0) {
        if (errno == EINTR) {
          continue;
        }
        return false;
      }
      if (got == 0) {
        return false;
      }
      offset += static_cast<std::size_t>(got);
    }
    return true;
  }

  /**
   * @brief Write an entire buffer.
   *
   * @param descriptor Client socket.
   * @param data Bytes to send.
   * @param size Byte count.
   * @return True when every byte was written.
   */
  bool write_fully(int descriptor, const void *data, std::size_t size) {
    auto *bytes = static_cast<const std::uint8_t *>(data);
    std::size_t offset = 0;
    while (offset < size) {
      const auto wrote = write(descriptor, bytes + offset, size - offset);
      if (wrote < 0) {
        if (errno == EINTR) {
          continue;
        }
        return false;
      }
      if (wrote == 0) {
        return false;
      }
      offset += static_cast<std::size_t>(wrote);
    }
    return true;
  }

  /**
   * @brief Parse a length-prefixed string out of the payload.
   *
   * @param payload Remaining bytes.
   * @param maximum Maximum accepted size.
   * @param value Destination.
   * @return True when a bounded string was consumed.
   */
  bool take_field(std::string_view &payload, std::size_t maximum, std::string &value) {
    if (payload.size() < 2) {
      return false;
    }
    const auto size = static_cast<std::size_t>(
      static_cast<unsigned char>(payload[0]) |
      (static_cast<unsigned>(static_cast<unsigned char>(payload[1])) << 8)
    );
    payload.remove_prefix(2);
    if (size > maximum || payload.size() < size) {
      return false;
    }
    value.assign(payload.data(), size);
    payload.remove_prefix(size);
    return value.find('\0') == std::string::npos;
  }

  /**
   * @brief Handle one media-worker request.
   *
   * @param descriptor Connected root-only client.
   */
  void serve_client(int descriptor) {
    ucred credentials {};
    socklen_t credential_size = sizeof(credentials);
    if (getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &credential_size) != 0 ||
        credential_size != sizeof(credentials) || credentials.uid != 0 || credentials.pid <= 0) {
      return;
    }

    std::array<std::uint8_t, 4> prefix {};
    if (!read_fully(descriptor, prefix.data(), prefix.size())) {
      return;
    }
    const auto length =
      static_cast<std::uint32_t>(prefix[0]) |
      (static_cast<std::uint32_t>(prefix[1]) << 8) |
      (static_cast<std::uint32_t>(prefix[2]) << 16) |
      (static_cast<std::uint32_t>(prefix[3]) << 24);
    if (length == 0 || length > maximum_payload) {
      return;
    }
    std::vector<std::uint8_t> payload(length);
    if (!read_fully(descriptor, payload.data(), payload.size()) || payload[0] != 1) {
      return;
    }
    struct payload_wiper_t {
      std::vector<std::uint8_t> *payload;
      ~payload_wiper_t() {
        if (payload != nullptr && !payload->empty()) {
          explicit_bzero(payload->data(), payload->size());
        }
      }
    } payload_wiper {&payload};
    std::string_view rest {
      reinterpret_cast<const char *>(payload.data() + 1),
      payload.size() - 1
    };
    std::string username;
    std::string session_id;
    if (!take_field(rest, plank::session::maximum_gdm_username, username) ||
        !plank::session::valid_gdm_username(username) ||
        !take_field(rest, plank::session::maximum_gdm_session_id, session_id) ||
        session_id.empty() || rest.empty()) {
      wipe_string(username);
      return;
    }
    const auto secret_count = static_cast<unsigned char>(rest[0]);
    rest.remove_prefix(1);
    if (secret_count == 0 || secret_count > plank::session::maximum_gdm_secrets) {
      wipe_string(username);
      return;
    }
    std::vector<std::string> secrets;
    secrets.reserve(secret_count);
    for (unsigned index = 0; index < secret_count; ++index) {
      std::string secret;
      if (!take_field(rest, plank::session::maximum_gdm_secret, secret) || secret.empty()) {
        wipe(secrets);
        wipe_string(username);
        return;
      }
      secrets.push_back(std::move(secret));
    }
    if (!rest.empty()) {
      wipe(secrets);
      wipe_string(username);
      return;
    }
    explicit_bzero(payload.data(), payload.size());
    payload.clear();

    int status_pipe[2] {-1, -1};
    if (pipe2(status_pipe, O_CLOEXEC) != 0) {
      wipe(secrets);
      wipe_string(username);
      return;
    }
    const pid_t child = fork();
    if (child < 0) {
      close(status_pipe[0]);
      close(status_pipe[1]);
      wipe(secrets);
      wipe_string(username);
      return;
    }
    if (child == 0) {
      close(status_pipe[0]);
      close(descriptor);
      const auto code = run_as_gdm(std::move(username), std::move(secrets), std::move(session_id));
      std::fflush(stderr);
      std::fflush(stdout);
      if (write(status_pipe[1], &code, 1) != 1) {
        _exit(1);
      }
      _exit(code == static_cast<unsigned char>(step_t::ok) ? 0 : 1);
    }
    close(status_pipe[1]);
    wipe(secrets);
    wipe_string(username);
    pollfd poll_status {status_pipe[0], POLLIN, 0};
    const int waited = poll(
      &poll_status,
      1,
      static_cast<int>(std::chrono::milliseconds {gdm_parent_wait}.count())
    );
    unsigned char byte = static_cast<unsigned char>(step_t::verify_timeout);
    if (waited > 0 && (poll_status.revents & POLLIN) != 0) {
      if (read(status_pipe[0], &byte, 1) != 1) {
        byte = static_cast<unsigned char>(step_t::verify_timeout);
      }
    } else {
      kill(child, SIGKILL);
    }
    close(status_pipe[0]);
    waitpid(child, nullptr, 0);
    write_fully(descriptor, &byte, 1);
  }

  /**
   * @brief Record termination so the accept loop exits.
   *
   * @param signal Delivered signal.
   */
  void handle_stop(int signal) {
    stopping = 1;
    if (listening_descriptor >= 0) {
      close(listening_descriptor);
      listening_descriptor = -1;
    }
    (void) signal;
  }

  /**
   * @brief Bind the root-only GDM login socket.
   *
   * @param path Absolute socket path.
   * @return Listener descriptor, or -1.
   */
  int bind_socket(const std::filesystem::path &path) {
    if (!path.is_absolute() || path.filename().empty()) {
      return -1;
    }
    std::error_code error;
    std::filesystem::remove(path, error);
    const int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
      return -1;
    }
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    const auto text = path.string();
    if (text.size() >= sizeof(address.sun_path)) {
      close(descriptor);
      return -1;
    }
    std::memcpy(address.sun_path, text.c_str(), text.size() + 1);
    if (bind(descriptor, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0 ||
        chmod(text.c_str(), 0600) != 0 ||
        listen(descriptor, 4) != 0) {
      close(descriptor);
      std::filesystem::remove(path, error);
      return -1;
    }
    return descriptor;
  }
}  // namespace

int main(int argc, char **argv) {
  if (geteuid() != 0) {
    std::cerr << "plank-gdm-login must run as root\n";
    return 3;
  }
  std::filesystem::path socket_path {plank::session::gdm_login_socket_path};
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument {argv[index]};
    if (argument == "--socket" && index + 1 < argc) {
      socket_path = argv[++index];
    } else {
      std::cerr << "usage: plank-gdm-login [--socket ABSOLUTE_PATH]\n";
      return 2;
    }
  }
  if (!socket_path.is_absolute()) {
    std::cerr << "GDM login socket must be an absolute path\n";
    return 2;
  }

  struct sigaction action {};
  action.sa_handler = handle_stop;
  sigemptyset(&action.sa_mask);
  sigaction(SIGTERM, &action, nullptr);
  sigaction(SIGINT, &action, nullptr);
  signal(SIGPIPE, SIG_IGN);

  const int listener = bind_socket(socket_path);
  if (listener < 0) {
    std::cerr << "Unable to listen on the GDM login socket\n";
    return 1;
  }
  listening_descriptor = listener;
  std::clog << "PLANK GDM login helper is listening\n";
  while (stopping == 0) {
    const int client = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    if (client < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (stopping != 0) {
        break;
      }
      std::cerr << "GDM login helper accept failed: " << std::strerror(errno) << '\n';
      break;
    }
    serve_client(client);
    close(client);
  }
  if (listening_descriptor >= 0) {
    close(listening_descriptor);
    listening_descriptor = -1;
  }
  std::error_code error;
  std::filesystem::remove(socket_path, error);
  return 0;
}
