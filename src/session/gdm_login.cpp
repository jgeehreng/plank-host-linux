/**
 * @file src/session/gdm_login.cpp
 * @brief Drive GDM 40's private UserVerifier after PLANK PAM.
 */
#include "gdm_login.h"

#include "session_context.h"
#include "../logging.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
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
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <string.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>
#include <unistd.h>

using namespace std::literals;

namespace plank::session {
  namespace {
    constexpr std::string_view gdm_account = "gdm";
    constexpr std::string_view gdm_service = "gdm-password";
    constexpr std::string_view session_path = "/org/gnome/DisplayManager/Session";
    constexpr std::string_view verifier_interface = "org.gnome.DisplayManager.UserVerifier";
    constexpr std::string_view greeter_interface = "org.gnome.DisplayManager.Greeter";
    constexpr std::size_t maximum_username = 256;
    constexpr std::size_t maximum_secret = 256;
    constexpr std::size_t maximum_secrets = 4;
    constexpr auto gdm_timeout = std::chrono::seconds {20};

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
      return setuid(ids.first) == 0 && geteuid() == ids.first;
    }

    /**
     * @brief Open GDM's private greeter bus.
     *
     * @param bus Destination for the started connection.
     * @return True when OpenSession returned a usable address.
     */
    bool open_gdm_session(sd_bus **bus) {
      sd_bus *system_bus = nullptr;
      if (sd_bus_open_system(&system_bus) < 0 || system_bus == nullptr) {
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
        if (sd_bus_error_is_set(&error)) {
          std::fprintf(stderr, "GDM OpenSession failed: %s\n", error.message);
        }
        sd_bus_error_free(&error);
        sd_bus_message_unref(reply);
        sd_bus_unref(system_bus);
        return false;
      }
      sd_bus *private_bus = nullptr;
      const int opened = sd_bus_new(&private_bus);
      const int addressed = opened >= 0 ? sd_bus_set_address(private_bus, address) : opened;
      const int client = addressed >= 0 ? sd_bus_set_bus_client(private_bus, 1) : addressed;
      const int started = client >= 0 ? sd_bus_start(private_bus) : client;
      sd_bus_error_free(&error);
      sd_bus_message_unref(reply);
      sd_bus_unref(system_bus);
      if (started < 0 || private_bus == nullptr) {
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
     * @return True when StartSessionWhenReady succeeded.
     */
    bool verify_and_start(std::string_view username, std::vector<std::string> &secrets) {
      sd_bus *bus = nullptr;
      if (!open_gdm_session(&bus) || bus == nullptr) {
        return false;
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
            session_path.data(),
            verifier_interface.data(),
            nullptr,
            handle_verifier_signal,
            &state
          ) < 0) {
        return false;
      }

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
        }
        sd_bus_error_free(&error);
        return false;
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
          return false;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
        if (sd_bus_wait(bus, static_cast<uint64_t>(remaining.count())) < 0) {
          return false;
        }
        while (sd_bus_process(bus, nullptr) > 0) {
        }
      }
      if (!state.complete) {
        return false;
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
      }
      sd_bus_message_unref(reply);
      sd_bus_error_free(&error);
      return status >= 0;
    }

    /**
     * @brief Child entry: join the greeter session, drop to gdm, and start the desktop.
     *
     * @param username PAM account.
     * @param secrets PAM responses.
     * @param greeter_session Active greeter logind session.
     * @return Process exit status, zero on success.
     */
    int run_as_gdm(
      std::string username,
      std::vector<std::string> secrets,
      std::string greeter_session
    ) {
      const auto ids = gdm_account_ids();
      if (!ids) {
        wipe(secrets);
        return 1;
      }
      if (!join_session_cgroup(greeter_session) || !become_gdm(*ids)) {
        wipe(secrets);
        return 1;
      }
      const bool started = verify_and_start(username, secrets);
      wipe(secrets);
      wipe_string(username);
      return started ? 0 : 1;
    }
  }  // namespace

  bool valid_gdm_username(std::string_view username) {
    return !username.empty() && username.size() <= maximum_username &&
           username.find('\0') == std::string_view::npos &&
           username.find('\n') == std::string_view::npos &&
           username.find('\r') == std::string_view::npos;
  }

  bool complete_gdm_login(std::string_view username, std::vector<std::string> &secrets) {
    struct wiper_t {
      std::vector<std::string> *secrets;
      ~wiper_t() {
        if (secrets != nullptr) {
          wipe(*secrets);
        }
      }
    } wiper {&secrets};

    if (!valid_gdm_username(username) || secrets.empty() || secrets.size() > maximum_secrets) {
      return false;
    }
    for (const auto &secret : secrets) {
      if (secret.empty() || secret.size() > maximum_secret ||
          secret.find('\0') != std::string::npos) {
        return false;
      }
    }
    if (geteuid() != 0) {
      return false;
    }
    const auto greeter = active_seat0_graphical_session();
    if (!greeter || greeter->session_class != "greeter") {
      return false;
    }

    int status_pipe[2] {-1, -1};
    if (pipe2(status_pipe, O_CLOEXEC) != 0) {
      return false;
    }
    const pid_t child = fork();
    if (child < 0) {
      close(status_pipe[0]);
      close(status_pipe[1]);
      return false;
    }
    if (child == 0) {
      close(status_pipe[0]);
      const int code = run_as_gdm(std::string {username}, secrets, greeter->id);
      wipe(secrets);
      const unsigned char byte = code == 0 ? 1 : 0;
      if (write(status_pipe[1], &byte, 1) != 1) {
        _exit(1);
      }
      _exit(code);
    }
    close(status_pipe[1]);
    pollfd poll_status {
      status_pipe[0],
      POLLIN,
      0
    };
    const int waited = poll(&poll_status, 1, static_cast<int>(std::chrono::milliseconds {gdm_timeout}.count()));
    unsigned char byte = 0;
    const bool ready = waited > 0 && (poll_status.revents & POLLIN) != 0 &&
                       read(status_pipe[0], &byte, 1) == 1;
    close(status_pipe[0]);
    if (!ready) {
      kill(child, SIGKILL);
    }
    waitpid(child, nullptr, 0);
    if (ready && byte == 1) {
      BOOST_LOG(info) << "GDM accepted the authenticated user session"sv;
      return true;
    }
    BOOST_LOG(warning) << "GDM did not start a user session after PAM"sv;
    return false;
  }
}  // namespace plank::session
