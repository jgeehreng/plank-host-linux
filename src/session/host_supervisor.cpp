/**
 * @file src/session/host_supervisor.cpp
 * @brief Boot-time PLANK graphical-session worker supervisor.
 */
#include "session_context.h"
#include "worker_control.h"
#include "../plank_topology.h"
#include "../auth/pam_broker_channel.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <poll.h>
#include <pwd.h>
#include <systemd/sd-login.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <grp.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
  constexpr std::string_view default_worker = "/usr/bin/plank-host";
  constexpr std::string_view machine_home = "/var/lib/plank";
  constexpr std::string_view runtime_pulse_cookie =
    "/run/plank/host/pulse-cookie";
  constexpr std::string_view systemctl_path = "/usr/bin/systemctl";
  constexpr std::string_view systemd_run_path = "/usr/bin/systemd-run";
  constexpr std::string_view display_prepare_path =
    "/usr/libexec/plank/plank-display-prepare";
  constexpr std::string_view xrandr_path = "/usr/bin/xrandr";
  constexpr std::string_view nvidia_settings_path = "/usr/bin/nvidia-settings";
  constexpr std::string_view display_overlay_path =
    "/etc/X11/xorg.conf.d/99-plank-headless.conf";
  constexpr std::string_view plank_config_path =
    "/etc/plank/host.conf";
  constexpr std::string_view runtime_display_state_path =
    "/run/plank/host/display-state";

  struct account_t {
    uid_t uid {};
    gid_t gid {};
    std::string name;
    std::string home;
  };

  struct worker_t {
    pid_t pid {-1};
    int control_descriptor {-1};
    std::string session_id;
    std::uint64_t generation {};
    int pam_descriptor {-1};  ///< Private descriptor-only broker delegation endpoint.
    bool greeter {false};
  };

  struct physical_output_t {
    std::string name;
    std::string mode;
    int native_width {};
    int native_height {};
    int x {};
  };

  struct physical_snapshot_t {
    std::string assignment;
    std::vector<physical_output_t> outputs;
  };

  struct physical_display_lease_t {
    uid_t uid {};
    plank::session::display_request_t request;
    std::string session_id;
    physical_snapshot_t snapshot;
    bool active {};
    std::chrono::steady_clock::time_point deadline;
  };

  std::optional<account_t> account_for_uid(uid_t uid) {
    constexpr std::size_t maximum_buffer = 1024U * 1024U;
    std::size_t size = 16384;
    std::vector<char> buffer(size);
    passwd record {};
    passwd *result = nullptr;
    while (true) {
      const int status = getpwuid_r(uid, &record, buffer.data(), buffer.size(), &result);
      if (status == 0 && result != nullptr) {
        return account_t {
          uid,
          record.pw_gid,
          record.pw_name == nullptr ? "" : record.pw_name,
          record.pw_dir == nullptr ? "" : record.pw_dir,
        };
      }
      if (status != ERANGE || buffer.size() >= maximum_buffer) {
        return std::nullopt;
      }
      buffer.resize(std::min(buffer.size() * 2, maximum_buffer));
    }
  }

  void set_environment_value(const char *name, const std::string &value) {
    if (!value.empty() && setenv(name, value.c_str(), 1) != 0) {
      std::cerr << "Unable to set " << name << ": " << std::strerror(errno) << '\n';
      std::_Exit(126);
    }
  }

  bool stage_pulse_cookie(const std::filesystem::path &source, uid_t uid) {
    constexpr off_t maximum_cookie_size = 4096;
    int source_descriptor = open(source.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source_descriptor < 0) return false;
    auto close_source = std::unique_ptr<int, std::function<void(int *)>> {
      &source_descriptor, [](int *descriptor) { close(*descriptor); }
    };

    struct stat source_status {};
    if (fstat(source_descriptor, &source_status) != 0 ||
        source_status.st_uid != uid || !S_ISREG(source_status.st_mode) ||
        source_status.st_size <= 0 || source_status.st_size > maximum_cookie_size) {
      return false;
    }

    int destination_descriptor = open(
      runtime_pulse_cookie.data(),
      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
      S_IRUSR | S_IWUSR
    );
    if (destination_descriptor < 0) return false;
    auto close_destination = std::unique_ptr<int, std::function<void(int *)>> {
      &destination_descriptor, [](int *descriptor) { close(*descriptor); }
    };
    if (fchmod(destination_descriptor, S_IRUSR | S_IWUSR) != 0) return false;

    std::array<char, 4096> buffer {};
    off_t copied = 0;
    while (copied < source_status.st_size) {
      const auto remaining = static_cast<std::size_t>(source_status.st_size - copied);
      const ssize_t received = read(
        source_descriptor, buffer.data(), std::min(buffer.size(), remaining)
      );
      if (received <= 0) return false;
      ssize_t offset = 0;
      while (offset < received) {
        const ssize_t written = write(
          destination_descriptor, buffer.data() + offset,
          static_cast<std::size_t>(received - offset)
        );
        if (written <= 0) return false;
        offset += written;
      }
      copied += received;
    }
    return fsync(destination_descriptor) == 0;
  }

  plank::session::environment_t add_audio_environment(
    plank::session::environment_t environment,
    const account_t &account
  ) {
    const std::filesystem::path pulse_socket =
      std::filesystem::path {environment.runtime_directory} / "pulse/native";
    const std::filesystem::path pulse_cookie =
      std::filesystem::path {account.home} / ".config/pulse/cookie";
    struct stat socket_status {};
    struct stat cookie_status {};
    if (lstat(pulse_socket.c_str(), &socket_status) == 0 &&
        socket_status.st_uid == account.uid && S_ISSOCK(socket_status.st_mode) &&
        lstat(pulse_cookie.c_str(), &cookie_status) == 0 &&
        cookie_status.st_uid == account.uid && S_ISREG(cookie_status.st_mode) &&
        stage_pulse_cookie(pulse_cookie, account.uid)) {
      environment.pulse_server = "unix:" + pulse_socket.string();
      environment.pulse_cookie = std::string {runtime_pulse_cookie};
    }
    return environment;
  }

  bool restrict_worker_capabilities() {
    __user_cap_header_struct header {
      _LINUX_CAPABILITY_VERSION_3,
      0,
    };
    std::array<__user_cap_data_struct, 2> capabilities {};
    constexpr auto capability = static_cast<unsigned int>(CAP_DAC_READ_SEARCH);
    constexpr auto word_bits = 32U;
    const auto mask = 1U << (capability % word_bits);
    capabilities[capability / word_bits].effective = mask;
    capabilities[capability / word_bits].permitted = mask;
    return syscall(SYS_capset, &header, capabilities.data()) == 0;
  }

  [[noreturn]] void launch_child(
    const std::filesystem::path &worker,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment,
    int control_descriptor,
    int supervisor_descriptor,
    int pam_descriptor,
    int supervisor_pam_descriptor
  ) {
    close(supervisor_descriptor);
    close(supervisor_pam_descriptor);
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() == 1) {
      std::_Exit(126);
    }
    sigset_t empty_mask;
    sigemptyset(&empty_mask);
    if (sigprocmask(SIG_SETMASK, &empty_mask, nullptr) != 0) {
      std::_Exit(126);
    }
    if (geteuid() != 0 || getegid() != 0) {
      std::cerr << "PLANK machine worker lost root identity\n";
      std::_Exit(126);
    }
    if (!restrict_worker_capabilities()) {
      std::cerr << "Unable to restrict machine worker capabilities: "
                << std::strerror(errno) << '\n';
      std::_Exit(126);
    }

    for (const int descriptor : {control_descriptor, pam_descriptor}) {
      const int descriptor_flags = fcntl(descriptor, F_GETFD);
      if (descriptor_flags < 0 ||
          fcntl(descriptor, F_SETFD, descriptor_flags & ~FD_CLOEXEC) != 0) {
        std::_Exit(126);
      }
    }
    clearenv();
    set_environment_value("HOME", std::string {machine_home});
    set_environment_value("USER", "root");
    set_environment_value("LOGNAME", "root");
    set_environment_value("SHELL", "/bin/sh");
    set_environment_value("PATH", "/usr/local/bin:/usr/bin:/bin");
    set_environment_value("DISPLAY", environment.display);
    set_environment_value("XAUTHORITY", environment.xauthority);
    set_environment_value("XDG_RUNTIME_DIR", environment.runtime_directory);
    set_environment_value("XDG_SESSION_ID", session.id);
    set_environment_value("XDG_SESSION_TYPE", session.type);
    set_environment_value("XDG_SESSION_CLASS", session.session_class);
    set_environment_value("XDG_SEAT", session.seat);
    set_environment_value("DBUS_SESSION_BUS_ADDRESS", environment.dbus_address);
    set_environment_value("PULSE_SERVER", environment.pulse_server);
    set_environment_value("PULSE_COOKIE", environment.pulse_cookie);
    set_environment_value(
      "PLANK_SESSION_CONTROL_FD", std::to_string(control_descriptor)
    );
    set_environment_value(
      plank::auth::broker_channel::environment_name, std::to_string(pam_descriptor)
    );
    if (chdir(machine_home.data()) != 0) {
      std::cerr << "Unable to enter machine worker home directory\n";
      std::_Exit(126);
    }
    execl(worker.c_str(), worker.c_str(), static_cast<char *>(nullptr));
    std::cerr << "Unable to execute PLANK worker: " << std::strerror(errno) << '\n';
    std::_Exit(127);
  }

  bool send_update(
    worker_t &worker,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment
  ) {
    const plank::session::update_t update {
      worker.generation + 1, session, environment
    };
    const std::string message = plank::session::session_update_message(update);
    if (message.empty()) {
      return false;
    }
    const ssize_t sent = send(
      worker.control_descriptor, message.data(), message.size(), MSG_NOSIGNAL
    );
    if (sent != static_cast<ssize_t>(message.size())) {
      return false;
    }
    pollfd response {worker.control_descriptor, POLLIN, 0};
    if (poll(&response, 1, 10000) != 1 || (response.revents & POLLIN) == 0) {
      return false;
    }
    std::array<char, 128> reply {};
    const ssize_t reply_size = recv(
      worker.control_descriptor, reply.data(), reply.size(), 0
    );
    const std::string expected =
      "SC-ACK-2\n" + std::to_string(update.generation) + "\nOK";
    if (reply_size != static_cast<ssize_t>(expected.size()) ||
        std::string_view {reply.data(), static_cast<std::size_t>(reply_size)} != expected) {
      return false;
    }
    worker.session_id = session.id;
    worker.generation = update.generation;
    worker.greeter = session.session_class == "greeter";
    return true;
  }

  worker_t launch_worker(
    const std::filesystem::path &worker,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment
  ) {
    int control_sockets[2] {-1, -1};
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control_sockets) != 0) {
      return {};
    }
    int pam_sockets[2] {-1, -1};
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pam_sockets) != 0) {
      close(control_sockets[0]);
      close(control_sockets[1]);
      return {};
    }
    const pid_t child = fork();
    if (child == 0) {
      launch_child(
        worker, session, environment, control_sockets[1], control_sockets[0],
        pam_sockets[1], pam_sockets[0]
      );
    }
    close(control_sockets[1]);
    close(pam_sockets[1]);
    if (child <= 0) {
      close(control_sockets[0]);
      close(pam_sockets[0]);
      return {};
    }
    worker_t result {child, control_sockets[0], {}, 0, pam_sockets[0], false};
    if (!send_update(result, session, environment)) {
      kill(child, SIGKILL);
      waitpid(child, nullptr, 0);
      close(control_sockets[0]);
      close(pam_sockets[0]);
      return {};
    }
    return result;
  }

  void stop_worker(worker_t &worker, bool opening_desktop = false) {
    if (worker.pid <= 0) {
      return;
    }
    const auto command = plank::session::desktop_handoff_command;
    const bool notified = opening_desktop && worker.greeter &&
      send(worker.control_descriptor, command.data(), command.size(),
           MSG_NOSIGNAL | MSG_DONTWAIT) == static_cast<ssize_t>(command.size());
    // The private command lets the worker notify the client before issuing its
    // own normal SIGTERM. Failure retains ordinary shutdown and reconnect UI.
    if (!notified) kill(worker.pid, SIGTERM);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {10};
    while (std::chrono::steady_clock::now() < deadline) {
      const pid_t result = waitpid(worker.pid, nullptr, WNOHANG);
      if (result == worker.pid || (result < 0 && errno == ECHILD)) {
        close(worker.control_descriptor);
        close(worker.pam_descriptor);
        worker = {};
        return;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds {50});
    }
    kill(worker.pid, SIGKILL);
    waitpid(worker.pid, nullptr, 0);
    close(worker.control_descriptor);
    close(worker.pam_descriptor);
    worker = {};
  }

  bool run_bounded_command(
    const std::filesystem::path &program,
    const std::vector<std::string> &arguments,
    std::chrono::seconds timeout
  ) {
    if (!program.is_absolute() || access(program.c_str(), X_OK) != 0) return false;
    const pid_t child = fork();
    if (child == 0) {
      std::vector<char *> command;
      command.reserve(arguments.size() + 2);
      command.push_back(const_cast<char *>(program.c_str()));
      for (const auto &argument : arguments) {
        command.push_back(const_cast<char *>(argument.c_str()));
      }
      command.push_back(nullptr);
      execv(program.c_str(), command.data());
      std::_Exit(127);
    }
    if (child <= 0) return false;

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    int status {};
    while (std::chrono::steady_clock::now() < deadline) {
      const pid_t result = waitpid(child, &status, WNOHANG);
      if (result == child) return WIFEXITED(status) && WEXITSTATUS(status) == 0;
      if (result < 0 && errno != EINTR) return false;
      std::this_thread::sleep_for(std::chrono::milliseconds {50});
    }
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
    return false;
  }

  std::optional<std::string> run_bounded_command_capture(
    const std::filesystem::path &program,
    const std::vector<std::string> &arguments,
    std::chrono::seconds timeout
  ) {
    constexpr std::size_t maximum_output_size = 64U * 1024U;
    if (!program.is_absolute() || access(program.c_str(), X_OK) != 0) {
      return std::nullopt;
    }
    int output_pipe[2] {-1, -1};
    if (pipe2(output_pipe, O_CLOEXEC | O_NONBLOCK) != 0) return std::nullopt;
    const pid_t child = fork();
    if (child == 0) {
      close(output_pipe[0]);
      if (dup2(output_pipe[1], STDOUT_FILENO) < 0) std::_Exit(127);
      close(output_pipe[1]);
      std::vector<char *> command;
      command.reserve(arguments.size() + 2);
      command.push_back(const_cast<char *>(program.c_str()));
      for (const auto &argument : arguments) {
        command.push_back(const_cast<char *>(argument.c_str()));
      }
      command.push_back(nullptr);
      execv(program.c_str(), command.data());
      std::_Exit(127);
    }
    close(output_pipe[1]);
    if (child <= 0) {
      close(output_pipe[0]);
      return std::nullopt;
    }

    std::string output;
    int status {};
    bool exited = false;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      std::array<char, 4096> buffer {};
      while (true) {
        const ssize_t size = read(output_pipe[0], buffer.data(), buffer.size());
        if (size > 0) {
          if (output.size() + static_cast<std::size_t>(size) > maximum_output_size) {
            kill(child, SIGKILL);
            waitpid(child, nullptr, 0);
            close(output_pipe[0]);
            return std::nullopt;
          }
          output.append(buffer.data(), static_cast<std::size_t>(size));
          continue;
        }
        if (size < 0 && errno != EAGAIN && errno != EINTR) {
          kill(child, SIGKILL);
          waitpid(child, nullptr, 0);
          close(output_pipe[0]);
          return std::nullopt;
        }
        break;
      }
      const pid_t result = waitpid(child, &status, WNOHANG);
      if (result == child) {
        exited = true;
        break;
      }
      if (result < 0 && errno != EINTR) break;
      pollfd descriptor {output_pipe[0], POLLIN, 0};
      poll(&descriptor, 1, 50);
    }
    if (!exited) {
      kill(child, SIGKILL);
      waitpid(child, nullptr, 0);
      close(output_pipe[0]);
      return std::nullopt;
    }
    std::array<char, 4096> tail {};
    while (true) {
      const ssize_t size = read(output_pipe[0], tail.data(), tail.size());
      if (size <= 0) break;
      if (output.size() + static_cast<std::size_t>(size) > maximum_output_size) {
        close(output_pipe[0]);
        return std::nullopt;
      }
      output.append(tail.data(), static_cast<std::size_t>(size));
    }
    close(output_pipe[0]);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ?
      std::optional<std::string> {std::move(output)} : std::nullopt;
  }

  bool run_bounded_user_command(
    const std::filesystem::path &program,
    const std::vector<std::string> &arguments,
    std::chrono::seconds timeout,
    const account_t &account,
    const plank::session::environment_t &environment
  ) {
    if (!program.is_absolute() || access(program.c_str(), X_OK) != 0 ||
        account.uid == 0 || account.name.empty()) return false;
    std::vector<std::string> transient_arguments {
      "--quiet", "--wait", "--collect", "--service-type=exec",
      "--uid=" + account.name,
      "--gid=" + std::to_string(account.gid),
      "--property=NoNewPrivileges=yes",
      "--property=ProtectSystem=strict",
      "--property=ProtectHome=yes",
      "--property=RestrictAddressFamilies=AF_UNIX",
      "--property=RuntimeMaxSec=" + std::to_string(timeout.count()) + "s",
      "--setenv=HOME=" + account.home,
      "--setenv=USER=" + account.name,
      "--setenv=LOGNAME=" + account.name,
      "--setenv=PATH=/usr/local/bin:/usr/bin:/bin",
      "--setenv=DISPLAY=" + environment.display,
      "--setenv=XAUTHORITY=" + environment.xauthority,
      "--setenv=XDG_RUNTIME_DIR=" + environment.runtime_directory,
      "--", program.string()
    };
    transient_arguments.insert(
      transient_arguments.end(), arguments.begin(), arguments.end()
    );
    return run_bounded_command(
      systemd_run_path, transient_arguments, timeout + std::chrono::seconds {2}
    );
  }

  std::optional<std::string> run_bounded_user_command_capture(
    const std::filesystem::path &program,
    const std::vector<std::string> &arguments,
    std::chrono::seconds timeout,
    const account_t &account,
    const plank::session::environment_t &environment
  ) {
    if (!program.is_absolute() || access(program.c_str(), X_OK) != 0 ||
        account.uid == 0 || account.name.empty()) return std::nullopt;
    std::vector<std::string> transient_arguments {
      "--quiet", "--pipe", "--wait", "--collect", "--service-type=exec",
      "--uid=" + account.name,
      "--gid=" + std::to_string(account.gid),
      "--property=NoNewPrivileges=yes",
      "--property=ProtectSystem=strict",
      "--property=ProtectHome=yes",
      "--property=RestrictAddressFamilies=AF_UNIX",
      "--property=RuntimeMaxSec=" + std::to_string(timeout.count()) + "s",
      "--setenv=HOME=" + account.home,
      "--setenv=USER=" + account.name,
      "--setenv=LOGNAME=" + account.name,
      "--setenv=PATH=/usr/local/bin:/usr/bin:/bin",
      "--setenv=DISPLAY=" + environment.display,
      "--setenv=XAUTHORITY=" + environment.xauthority,
      "--setenv=XDG_RUNTIME_DIR=" + environment.runtime_directory,
      "--", program.string()
    };
    transient_arguments.insert(
      transient_arguments.end(), arguments.begin(), arguments.end()
    );
    return run_bounded_command_capture(
      systemd_run_path, transient_arguments, timeout + std::chrono::seconds {2}
    );
  }

  std::string_view trim_view(std::string_view value) {
    constexpr std::string_view whitespace = " \t\r\n";
    const auto first = value.find_first_not_of(whitespace);
    if (first == std::string_view::npos) return {};
    const auto last = value.find_last_not_of(whitespace);
    return value.substr(first, last - first + 1);
  }

  std::optional<int> parse_positive_int(std::string_view value) {
    int parsed {};
    const auto result = std::from_chars(
      value.data(), value.data() + value.size(), parsed
    );
    if (value.empty() || result.ec != std::errc {} ||
        result.ptr != value.data() + value.size() || parsed <= 0) {
      return std::nullopt;
    }
    return parsed;
  }

  std::optional<physical_snapshot_t> parse_current_metamode(
    std::string_view response
  ) {
    constexpr std::size_t maximum_assignment_size = 32U * 1024U;
    const auto separator = response.find("::");
    if (separator == std::string_view::npos) return std::nullopt;
    const auto assignment_view = trim_view(response.substr(separator + 2));
    if (assignment_view.empty() || assignment_view.size() > maximum_assignment_size) {
      return std::nullopt;
    }
    for (const unsigned char character : assignment_view) {
      if (character < 0x20 || character > 0x7e) return std::nullopt;
    }

    std::vector<std::string_view> clauses;
    std::size_t start = 0;
    int brace_depth = 0;
    for (std::size_t index = 0; index <= assignment_view.size(); ++index) {
      const char character = index < assignment_view.size() ? assignment_view[index] : ',';
      if (character == '{') ++brace_depth;
      else if (character == '}') --brace_depth;
      if (brace_depth < 0) return std::nullopt;
      if (character == ',' && brace_depth == 0) {
        clauses.push_back(trim_view(assignment_view.substr(start, index - start)));
        start = index + 1;
      }
    }
    if (brace_depth != 0 || clauses.empty()) return std::nullopt;

    static const std::regex output_name {R"(^[A-Za-z0-9_-]+$)"};
    static const std::regex viewport_out {
      R"(ViewPortOut=([0-9]+)x([0-9]+)\+[0-9]+\+[0-9]+)"
    };
    static const std::regex logical_position {
      R"(@[0-9]+x[0-9]+ \+([0-9]+)\+[0-9]+)"
    };
    physical_snapshot_t snapshot;
    snapshot.assignment = std::string {assignment_view};
    for (const auto clause : clauses) {
      const auto colon = clause.find(':');
      if (colon == std::string_view::npos) return std::nullopt;
      const std::string name {trim_view(clause.substr(0, colon))};
      const auto body = trim_view(clause.substr(colon + 1));
      if (!std::regex_match(name, output_name)) return std::nullopt;
      if (body == "NULL") continue;
      const auto mode_end = body.find_first_of(" \t");
      if (mode_end == std::string_view::npos) return std::nullopt;
      const std::string mode {body.substr(0, mode_end)};
      if (!std::regex_match(mode, output_name)) return std::nullopt;
      std::match_results<std::string_view::const_iterator> viewport_match;
      std::match_results<std::string_view::const_iterator> position_match;
      if (!std::regex_search(body.begin(), body.end(), viewport_match, viewport_out) ||
          !std::regex_search(body.begin(), body.end(), position_match, logical_position)) {
        return std::nullopt;
      }
      const auto width = parse_positive_int(
        std::string_view {viewport_match[1].first, viewport_match[1].second}
      );
      const auto height = parse_positive_int(
        std::string_view {viewport_match[2].first, viewport_match[2].second}
      );
      const auto x = parse_positive_int(
        std::string_view {position_match[1].first, position_match[1].second}
      );
      // The leftmost output legitimately begins at zero.
      int parsed_x = 0;
      const auto x_view = std::string_view {
        position_match[1].first, position_match[1].second
      };
      const auto x_result = std::from_chars(
        x_view.data(), x_view.data() + x_view.size(), parsed_x
      );
      if (!width || !height || x_result.ec != std::errc {} ||
          x_result.ptr != x_view.data() + x_view.size() || parsed_x < 0) {
        return std::nullopt;
      }
      (void) x;
      snapshot.outputs.push_back({name, mode, *width, *height, parsed_x});
    }
    if (snapshot.outputs.empty()) return std::nullopt;
    std::sort(snapshot.outputs.begin(), snapshot.outputs.end(), [](const auto &left,
                                                                  const auto &right) {
      return std::tie(left.x, left.name) < std::tie(right.x, right.name);
    });
    return snapshot;
  }

  std::optional<physical_snapshot_t> capture_physical_snapshot(
    const account_t &account,
    const plank::session::environment_t &environment
  ) {
    const auto response = run_bounded_user_command_capture(
      nvidia_settings_path, {"--query", "CurrentMetaMode", "--terse"},
      std::chrono::seconds {10}, account, environment
    );
    return response ? parse_current_metamode(*response) : std::nullopt;
  }

  bool assign_metamode(
    std::string_view assignment,
    const account_t &account,
    const plank::session::environment_t &environment
  ) {
    return !assignment.empty() && run_bounded_user_command(
      nvidia_settings_path,
      {"--assign", "CurrentMetaMode=" + std::string {assignment}},
      std::chrono::seconds {10}, account, environment
    );
  }

  std::optional<std::string> temporary_metamode(
    const physical_snapshot_t &snapshot,
    const plank::session::display_request_t &request
  ) {
    const std::size_t required_outputs =
      request.layout == "dual-horizontal" ? 2U : 1U;
    if (snapshot.outputs.size() < required_outputs) return std::nullopt;
    const std::array<std::string_view, 2> modes {request.mode_1, request.mode_2};
    std::string assignment;
    int x = 0;
    for (std::size_t index = 0; index < required_outputs; ++index) {
      const auto requested = plank::topology::virtual_mode_size(modes[index]);
      const auto &physical = snapshot.outputs[index];
      if (requested.width <= 0 || requested.height <= 0) return std::nullopt;
      if (!assignment.empty()) assignment += ", ";
      assignment += physical.name + ": " + physical.mode + " @" +
        std::to_string(requested.width) + "x" + std::to_string(requested.height) +
        " +" + std::to_string(x) + "+0 {ViewPortIn=" +
        std::to_string(requested.width) + "x" + std::to_string(requested.height) +
        ", ViewPortOut=" + std::to_string(physical.native_width) + "x" +
        std::to_string(physical.native_height) + "+0+0}";
      x += requested.width;
    }
    return assignment;
  }

  std::string safe_physical_metamode(const physical_snapshot_t &snapshot) {
    if (snapshot.outputs.empty()) return {};
    const auto &output = snapshot.outputs.front();
    return output.name + ": " + output.mode + " @" +
      std::to_string(output.native_width) + "x" +
      std::to_string(output.native_height) + " +0+0 {ViewPortIn=" +
      std::to_string(output.native_width) + "x" +
      std::to_string(output.native_height) + ", ViewPortOut=" +
      std::to_string(output.native_width) + "x" +
      std::to_string(output.native_height) + "+0+0}";
  }

  bool write_runtime_display_state(
    const plank::session::runtime_display_state_t &state
  ) {
    const std::string contents =
      plank::session::runtime_display_state_message(state);
    if (contents.empty()) return false;
    const std::string temporary = std::string {runtime_display_state_path} +
      ".tmp." + std::to_string(getpid());
    const int descriptor = open(
      temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
      S_IRUSR | S_IWUSR
    );
    if (descriptor < 0) return false;
    ssize_t offset = 0;
    while (offset < static_cast<ssize_t>(contents.size())) {
      const ssize_t written = write(
        descriptor, contents.data() + offset, contents.size() - offset
      );
      if (written <= 0) break;
      offset += written;
    }
    const bool complete = offset == static_cast<ssize_t>(contents.size()) &&
      fsync(descriptor) == 0 && close(descriptor) == 0 &&
      rename(temporary.c_str(), runtime_display_state_path.data()) == 0;
    if (!complete) {
      close(descriptor);
      unlink(temporary.c_str());
    }
    return complete;
  }

  void clear_runtime_display_state() {
    if (unlink(runtime_display_state_path.data()) != 0 && errno != ENOENT) {
      std::cerr << "Unable to remove the PLANK runtime display state: "
                << std::strerror(errno) << '\n';
    }
  }

  bool apply_physical_lease(
    physical_display_lease_t &lease,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment
  ) {
    const auto account = account_for_uid(session.uid);
    if (!account) return false;
    const auto snapshot = capture_physical_snapshot(*account, environment);
    if (!snapshot) {
      std::cerr << "Unable to capture the physical NVIDIA MetaMode before the PLANK session\n";
      return false;
    }
    const auto temporary = temporary_metamode(*snapshot, lease.request);
    if (!temporary || !assign_metamode(*temporary, *account, environment)) {
      std::cerr << "Unable to apply the temporary PLANK physical-display layout\n";
      return false;
    }
    if (!write_runtime_display_state({
          lease.request.layout, lease.request.mode_1, lease.request.mode_2,
          lease.uid
        })) {
      assign_metamode(snapshot->assignment, *account, environment);
      std::cerr << "Unable to publish the temporary PLANK display state; restored the physical layout\n";
      return false;
    }
    lease.session_id = session.id;
    lease.snapshot = *snapshot;
    return true;
  }

  bool restore_physical_lease(
    const physical_display_lease_t &lease,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment
  ) {
    const auto account = account_for_uid(session.uid);
    if (!account) return false;
    if (assign_metamode(lease.snapshot.assignment, *account, environment)) {
      clear_runtime_display_state();
      std::clog << "Restored the exact pre-session physical NVIDIA MetaMode\n";
      return true;
    }
    const auto fallback = safe_physical_metamode(lease.snapshot);
    const bool recovered = !fallback.empty() &&
      assign_metamode(fallback, *account, environment);
    clear_runtime_display_state();
    std::cerr << "ERROR: Exact PLANK physical-display restoration failed; "
              << (recovered ? "enabled one safe native physical output" :
                              "safe physical-output recovery also failed")
              << '\n';
    return recovered;
  }

  bool apply_live_display_transition(
    const plank::session::display_request_t &request,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment
  ) {
    const auto account = account_for_uid(session.uid);
    const auto first = plank::topology::virtual_mode_size(request.mode_1);
    const auto second = plank::topology::virtual_mode_size(request.mode_2);
    if (!account || first.width <= 0 || first.height <= 0 ||
        (request.layout == "dual-horizontal" &&
         (second.width <= 0 || second.height <= 0))) {
      return false;
    }

    const auto layout_arguments = [&](const std::string &mode_1,
                                      const std::string &mode_2) {
      const int canvas_width = first.width +
        (request.layout == "dual-horizontal" ? second.width : 0);
      const int canvas_height = request.layout == "dual-horizontal" ?
        std::max(first.height, second.height) : first.height;
      std::vector<std::string> arguments {
        "--fb", std::to_string(canvas_width) + "x" + std::to_string(canvas_height),
        "--output", "DP-0", "--mode", mode_1, "--rate", "60",
        "--pos", "0x0", "--primary"
      };
      if (request.layout == "dual-horizontal") {
        arguments.insert(arguments.end(), {
          "--output", "DP-2", "--set", "non-desktop", "0",
          "--mode", mode_2, "--rate", "60",
          "--pos", std::to_string(first.width) + "x0"
        });
      } else {
        arguments.insert(arguments.end(), {
          "--output", "DP-2", "--off", "--set", "non-desktop", "1"
        });
      }
      return arguments;
    };

    // Every qualified mode is part of each virtual monitor's EDID. NVIDIA
    // validates this pool at Xorg startup, so live transitions never inject
    // or approve an ad hoc timing.
    return run_bounded_user_command(
      xrandr_path,
      layout_arguments(request.mode_1, request.mode_2),
      std::chrono::seconds {10}, *account, environment
    );
  }

  std::optional<bool> overlay_secondary_visibility() {
    constexpr std::size_t maximum_overlay_size = 64U * 1024U;
    std::ifstream input {display_overlay_path.data(), std::ios::binary};
    if (!input) return std::nullopt;
    std::string contents(
      std::istreambuf_iterator<char> {input}, std::istreambuf_iterator<char> {}
    );
    if (contents.size() > maximum_overlay_size) return std::nullopt;
    return plank::session::secondary_output_visible_from_overlay(contents);
  }

  bool set_secondary_desktop_visibility(
    bool visible,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment
  ) {
    const auto account = account_for_uid(session.uid);
    if (!account) return false;
    const std::vector<std::string> arguments = visible ?
      std::vector<std::string> {"--output", "DP-2", "--set", "non-desktop", "0"} :
      std::vector<std::string> {
        "--output", "DP-2", "--off", "--set", "non-desktop", "1"
      };
    return run_bounded_user_command(
      xrandr_path, arguments, std::chrono::seconds {10}, *account, environment
    );
  }

  bool apply_display_transition(const plank::session::display_request_t &request) {
    const bool stopped = run_bounded_command(
      systemctl_path, {"stop", "display-manager.service"}, std::chrono::seconds {30}
    );
    if (!stopped) {
      std::cerr << "Unable to stop the display manager for PLANK topology transition\n";
      return false;
    }

    std::vector<std::string> prepare_arguments {
      "--layout", request.layout, "--mode-1", request.mode_1
    };
    if (!request.mode_2.empty()) {
      prepare_arguments.insert(
        prepare_arguments.end(), {"--mode-2", request.mode_2}
      );
    }
    const bool prepared = run_bounded_command(
      display_prepare_path, prepare_arguments, std::chrono::seconds {15}
    );
    const bool started = run_bounded_command(
      systemctl_path, {"start", "display-manager.service"}, std::chrono::seconds {30}
    );
    if (!prepared) {
      std::cerr << "PLANK display preparation failed; restored the prior GDM topology\n";
    }
    if (!started) {
      std::cerr << "Unable to restart the display manager after PLANK topology transition\n";
    }
    return prepared && started;
  }

  void usage(const char *program) {
    std::cerr << "usage: " << program << " [--worker ABSOLUTE_PATH]\n";
  }
}  // namespace

int main(int argc, char **argv) {
  std::filesystem::path worker_path {default_worker};
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument {argv[index]};
    if (argument == "--worker" && index + 1 < argc) {
      worker_path = argv[++index];
    } else {
      usage(argv[0]);
      return 2;
    }
  }
  if (geteuid() != 0) {
    std::cerr << "plank-host-supervisor must run as root\n";
    return 3;
  }
  if (!worker_path.is_absolute() || access(worker_path.c_str(), X_OK) != 0) {
    std::cerr << "PLANK worker is unavailable: " << worker_path << '\n';
    return 4;
  }
  sigset_t signal_mask;
  sigemptyset(&signal_mask);
  sigaddset(&signal_mask, SIGTERM);
  sigaddset(&signal_mask, SIGINT);
  sigaddset(&signal_mask, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &signal_mask, nullptr) != 0) {
    return 6;
  }
  const int signal_fd = signalfd(-1, &signal_mask, SFD_CLOEXEC | SFD_NONBLOCK);
  if (signal_fd < 0) {
    return 7;
  }
  sd_login_monitor *raw_monitor = nullptr;
  if (sd_login_monitor_new("session", &raw_monitor) < 0 || raw_monitor == nullptr) {
    close(signal_fd);
    return 8;
  }
  std::unique_ptr<sd_login_monitor, decltype(&sd_login_monitor_unref)> monitor {
    raw_monitor, &sd_login_monitor_unref
  };

  worker_t worker;
  std::optional<plank::session::display_request_t> pending_display_request;
  std::optional<physical_display_lease_t> physical_display_lease;
  const auto startup_layout =
    plank::session::configured_startup_layout(plank_config_path);
  const bool physical_startup =
    startup_layout == plank::session::startup_layout_t::physical;
  const bool virtual_startup =
    startup_layout == plank::session::startup_layout_t::virtual_display;
  if (startup_layout == plank::session::startup_layout_t::invalid) {
    std::cerr << "PLANK startup display policy is invalid; display transitions are disabled\n";
  }
  bool recover_stale_runtime_state = physical_startup &&
    plank::session::read_runtime_display_state(
      runtime_display_state_path
    ).has_value();
  std::optional<bool> desired_secondary_visibility =
    virtual_startup ? overlay_secondary_visibility() : std::nullopt;
  bool initial_secondary_visibility = desired_secondary_visibility.has_value();
  std::string visibility_session_id;
  auto display_request_deadline = std::chrono::steady_clock::time_point::max();
  std::string pending_session;
  auto next_launch = std::chrono::steady_clock::now();
  bool stopping = false;
  while (!stopping) {
    if (physical_display_lease && !physical_display_lease->active &&
        std::chrono::steady_clock::now() >= physical_display_lease->deadline) {
      const auto selected = plank::session::active_seat0_graphical_session();
      const auto environment = selected &&
        selected->id == physical_display_lease->session_id ?
          plank::session::discover_environment(*selected) : std::nullopt;
      if (selected && environment) {
        restore_physical_lease(*physical_display_lease, *selected, *environment);
      } else {
        clear_runtime_display_state();
        std::cerr << "Temporary PLANK display lease expired after its X server disappeared\n";
      }
      physical_display_lease.reset();
    }

    if (pending_display_request &&
        std::chrono::steady_clock::now() >= display_request_deadline) {
      const auto selected = plank::session::active_seat0_graphical_session();
      if (!selected || selected->id != worker.session_id) {
        std::cerr << "Refusing PLANK display transition because the graphical session changed\n";
      } else if (physical_startup) {
        const auto environment = plank::session::discover_environment(*selected);
        physical_display_lease_t lease {
          pending_display_request->account_uid, *pending_display_request, {}, {}, false,
          std::chrono::steady_clock::now() + std::chrono::seconds {45}
        };
        if (!environment) {
          std::cerr << "Unable to discover the active X11 environment for a temporary physical-display lease\n";
        } else if (physical_display_lease &&
                   physical_display_lease->uid != lease.uid) {
          std::cerr << "Refusing to replace a temporary display lease owned by another account\n";
        } else if (apply_physical_lease(lease, *selected, *environment)) {
          physical_display_lease = std::move(lease);
          std::clog << "Temporary PLANK physical-display lease acquired for UID "
                    << physical_display_lease->uid << '\n';
        }
      } else if (!virtual_startup) {
        std::cerr << "Refusing a display transition because display.startup_layout is invalid\n";
      } else if (selected->session_class == "greeter") {
        const auto request = std::move(*pending_display_request);
        std::clog << "Applying PLANK display transition: "
                  << request.layout << ' ' << request.mode_1;
        if (!request.mode_2.empty()) std::clog << ' ' << request.mode_2;
        std::clog << '\n';
        stop_worker(worker);
        if (apply_display_transition(request)) {
          desired_secondary_visibility = request.layout == "dual-horizontal";
          visibility_session_id.clear();
          initial_secondary_visibility = false;
          std::clog << "PLANK display transition completed\n";
        }
      } else if (selected->session_class == "user" &&
                 selected->uid == pending_display_request->account_uid) {
        const auto environment = plank::session::discover_environment(*selected);
        if (!environment) {
          std::cerr << "Unable to discover the active user's X11 environment for a live display transition\n";
        } else if (apply_live_display_transition(
                     *pending_display_request, *selected, *environment
                   )) {
          desired_secondary_visibility =
            pending_display_request->layout == "dual-horizontal";
          visibility_session_id = selected->id;
          initial_secondary_visibility = false;
          std::clog << "PLANK live display transition completed for UID "
                    << selected->uid << '\n';
        } else {
          std::cerr << "PLANK live display transition failed for UID "
                    << selected->uid << '\n';
        }
      } else {
        std::cerr << "Refusing PLANK display transition for a user other than the active desktop owner\n";
      }
      pending_display_request.reset();
      display_request_deadline = std::chrono::steady_clock::time_point::max();
      next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
      continue;
    }

    const auto selected = plank::session::active_seat0_graphical_session();
    if (!selected) {
      pending_session.clear();
    } else if ((worker.pid <= 0 || worker.session_id != selected->id) &&
               std::chrono::steady_clock::now() >= next_launch) {
      const auto environment = plank::session::discover_environment(*selected);
      const auto account = account_for_uid(selected->uid);
      if (!environment || !account || account->home.empty()) {
        if (pending_session != selected->id) {
          std::clog << "Waiting for graphical environment for seat0 session "
                    << selected->id << '\n';
          pending_session = selected->id;
        }
      } else {
        const auto confirmed = plank::session::active_seat0_graphical_session();
        if (!confirmed || confirmed->id != selected->id || confirmed->uid != selected->uid) {
          continue;
        }
        if (worker.pid > 0 && worker.session_id != selected->id) {
          const auto previous_session = worker.session_id;
          std::clog << "Graphical session changed from " << previous_session
                    << " to " << selected->id
                    << "; restarting the PLANK media worker for fresh X11/NvFBC state\n";
          stop_worker(worker, selected->session_class == "user");
        }

        if (recover_stale_runtime_state) {
          const auto stale_snapshot = capture_physical_snapshot(*account, *environment);
          const auto fallback = stale_snapshot ?
            safe_physical_metamode(*stale_snapshot) : std::string {};
          if (!fallback.empty() && assign_metamode(fallback, *account, *environment)) {
            std::cerr << "Recovered a stale temporary PLANK layout with one safe native physical output\n";
          } else {
            std::cerr << "ERROR: Unable to recover the stale temporary PLANK physical layout\n";
          }
          clear_runtime_display_state();
          recover_stale_runtime_state = false;
        }

        if (physical_display_lease &&
            physical_display_lease->session_id != selected->id) {
          if (selected->session_class == "user" &&
              selected->uid == physical_display_lease->uid) {
            if (!apply_physical_lease(
                  *physical_display_lease, *selected, *environment
                )) {
              clear_runtime_display_state();
              physical_display_lease.reset();
              std::cerr << "Unable to carry the temporary display lease from GDM into the authenticated desktop\n";
            } else {
              std::clog << "Carried the temporary PLANK display lease into user session "
                        << selected->id << '\n';
            }
          } else {
            clear_runtime_display_state();
            physical_display_lease.reset();
            std::clog << "Discarded the temporary display lease after its X server ended\n";
          }
        }

        const auto complete_environment = add_audio_environment(*environment, *account);
        if (desired_secondary_visibility && visibility_session_id != selected->id) {
          // An existing user X server retains this connector property across
          // a supervisor restart, so do not replace its live state with a
          // potentially older boot overlay. Once the supervisor has observed
          // or changed a visibility state, reapply it to every newly created
          // GDM or user X server before launching that session's worker.
          if (initial_secondary_visibility && selected->session_class == "user") {
            desired_secondary_visibility.reset();
            visibility_session_id.clear();
            initial_secondary_visibility = false;
          } else if (!set_secondary_desktop_visibility(
                       *desired_secondary_visibility, *selected, *environment
                     )) {
            std::cerr << "Unable to apply PLANK secondary-monitor visibility\n";
            next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
            continue;
          } else {
            std::clog << "PLANK secondary virtual monitor is "
                      << (*desired_secondary_visibility ? "available" : "hidden")
                      << " to the desktop\n";
            visibility_session_id = selected->id;
            initial_secondary_visibility = false;
          }
        }
        if (worker.pid <= 0) {
          auto launched = launch_worker(worker_path, *selected, complete_environment);
          if (launched.pid > 0) {
            worker = std::move(launched);
            pending_session.clear();
            std::clog << "Attached persistent PLANK machine worker to session "
                      << selected->id << ", UID " << selected->uid << '\n';
          } else {
            std::cerr << "Unable to fork PLANK worker: " << std::strerror(errno) << '\n';
          }
        }
        if (worker.pid > 0) {
          pending_session.clear();
        }
        next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
      }
    }

    std::array<pollfd, 4> descriptors {{
      {signal_fd, POLLIN, 0},
      {sd_login_monitor_get_fd(monitor.get()), POLLIN, 0},
      {worker.control_descriptor, POLLIN, 0},
      {worker.pam_descriptor, POLLIN, 0},
    }};
    const int status = poll(descriptors.data(), descriptors.size(), 1000);
    if (status < 0 && errno != EINTR) {
      std::cerr << "Supervisor poll failed: " << std::strerror(errno) << '\n';
      break;
    }
    if ((descriptors[1].revents & POLLIN) != 0) {
      sd_login_monitor_flush(monitor.get());
    }
    if ((descriptors[3].revents & (POLLIN | POLLHUP | POLLERR)) != 0 && worker.pid > 0) {
      namespace delegation = plank::auth::broker_channel;
      int unexpected_descriptor = -1;
      const bool valid = delegation::receive_record(
        worker.pam_descriptor, delegation::request_byte, false, unexpected_descriptor);
      const auto active = plank::session::active_seat0_graphical_session();
      const int broker = valid && active && active->id == worker.session_id ?
        delegation::connect_broker() : -1;
      const bool sent = valid && delegation::send_connection(worker.pam_descriptor, broker);
      if (broker >= 0) close(broker);
      if (!sent) {
        close(worker.pam_descriptor);
        worker.pam_descriptor = -1;
        std::cerr << "PLANK private PAM delegation channel closed\n";
      }
    }
    if ((descriptors[2].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0 && worker.pid > 0) {
      std::array<char, 8193> message {};
      const ssize_t size = plank::session::receive_worker_control(
        worker.control_descriptor, message.data(), message.size());
      if (size > 0) {
        const auto request = static_cast<std::size_t>(size) <= message.size() ? plank::session::parse_display_request(
          std::string_view {message.data(), static_cast<std::size_t>(size)}
        ) : std::nullopt;
        const auto active = plank::session::active_seat0_graphical_session();
        if (!request) {
          std::cerr << "Rejected malformed PLANK display transition request\n";
        } else if (!active || active->id != worker.session_id ||
                   (active->session_class == "user" &&
                    active->uid != request->account_uid) ||
                   (active->session_class != "greeter" &&
                    active->session_class != "user")) {
          std::cerr << "Refused PLANK display transition outside an authorized graphical session\n";
        } else if (request->action ==
                     plank::session::display_request_t::action_t::activate) {
          if (physical_display_lease &&
              physical_display_lease->uid == request->account_uid) {
            physical_display_lease->active = true;
            physical_display_lease->deadline =
              std::chrono::steady_clock::time_point::max();
            std::clog << "Temporary PLANK display lease is active\n";
          }
        } else if (request->action ==
                     plank::session::display_request_t::action_t::release) {
          if (physical_display_lease &&
              physical_display_lease->uid == request->account_uid) {
            const auto environment = active->id == physical_display_lease->session_id ?
              plank::session::discover_environment(*active) : std::nullopt;
            if (environment) {
              restore_physical_lease(*physical_display_lease, *active, *environment);
            } else {
              clear_runtime_display_state();
              std::cerr << "Released a temporary display lease after its X server disappeared\n";
            }
            physical_display_lease.reset();
          }
        } else if (!pending_display_request) {
          pending_display_request = *request;
          // Allow the HTTPS worker to return its transition response before it
          // is stopped and GDM is restarted.
          display_request_deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds {750};
          std::clog << "Scheduled PLANK display transition from "
                    << (active->session_class == "greeter" ? "GDM" : "the active user desktop")
                    << '\n';
        }
      }
    }
    if ((descriptors[0].revents & POLLIN) != 0) {
      signalfd_siginfo information {};
      while (read(signal_fd, &information, sizeof(information)) == sizeof(information)) {
        if (information.ssi_signo == SIGTERM || information.ssi_signo == SIGINT) {
          stopping = true;
        } else if (information.ssi_signo == SIGCHLD && worker.pid > 0) {
          const pid_t result = waitpid(worker.pid, nullptr, WNOHANG);
          if (result == worker.pid) {
            std::clog << "PLANK worker exited; scheduling restart\n";
            if (physical_display_lease && physical_display_lease->active &&
                physical_display_lease->session_id == worker.session_id) {
              physical_display_lease->active = false;
              physical_display_lease->deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds {30};
              std::cerr << "PLANK worker exited with an active display lease; allowing 30 seconds for recovery\n";
            }
            close(worker.control_descriptor);
            close(worker.pam_descriptor);
            worker = {};
            next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
          }
        }
      }
    }
  }

  if (physical_display_lease) {
    const auto selected = plank::session::active_seat0_graphical_session();
    const auto environment = selected &&
      selected->id == physical_display_lease->session_id ?
        plank::session::discover_environment(*selected) : std::nullopt;
    if (selected && environment) {
      restore_physical_lease(*physical_display_lease, *selected, *environment);
    } else {
      clear_runtime_display_state();
    }
  }
  stop_worker(worker);
  close(signal_fd);
  return 0;
}
