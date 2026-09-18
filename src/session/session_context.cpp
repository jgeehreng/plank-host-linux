/**
 * @file src/session/session_context.cpp
 * @brief Logind-backed graphical-session selection and desktop reattachment.
 */
#include "session_context.h"

#include "../plank_topology.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <stop_token>
#include <thread>
#include <vector>

#include <systemd/sd-login.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace plank::session {
  namespace {
    constexpr std::string_view update_prefix = "SC-SESSION-2";
    constexpr std::string_view display_request_prefix = "SC-DISPLAY-3";
    constexpr std::string_view runtime_display_state_prefix = "SC-DISPLAY-STATE-1";
    constexpr std::size_t maximum_update_size = 8192;
    using login_string_t = std::unique_ptr<char, decltype(&free)>;

    std::mutex current_update_mutex;
    std::optional<update_t> current_update;
    std::atomic_uint64_t current_generation {};
    std::mutex supervisor_descriptor_mutex;
    int supervisor_descriptor {-1};

    std::optional<std::string> session_string(
      int (*getter)(const char *, char **),
      std::string_view session_id
    ) {
      char *raw = nullptr;
      const std::string id {session_id};
      if (getter(id.c_str(), &raw) < 0 || raw == nullptr) return std::nullopt;
      login_string_t value {raw, &free};
      return std::string {value.get()};
    }

    bool owned_path(const std::filesystem::path &path, uid_t uid, bool directory) {
      struct stat status {};
      if (lstat(path.c_str(), &status) != 0 || status.st_uid != uid) return false;
      return directory ? S_ISDIR(status.st_mode) : S_ISREG(status.st_mode);
    }

    bool owned_socket(const std::filesystem::path &path, uid_t uid) {
      struct stat status {};
      return lstat(path.c_str(), &status) == 0 && status.st_uid == uid &&
             S_ISSOCK(status.st_mode);
    }

    std::optional<pid_t> parse_pid(const std::filesystem::path &path) {
      const auto name = path.filename().string();
      pid_t pid {};
      const auto result = std::from_chars(name.data(), name.data() + name.size(), pid);
      if (result.ec != std::errc {} || result.ptr != name.data() + name.size() || pid <= 0) {
        return std::nullopt;
      }
      return pid;
    }

    std::map<std::string, std::string> read_selected_environment(pid_t pid) {
      constexpr std::size_t maximum_environment_size = 1024U * 1024U;
      const std::array<std::string_view, 4> allowed {
        "DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"
      };
      std::ifstream input {"/proc/" + std::to_string(pid) + "/environ", std::ios::binary};
      if (!input) return {};
      std::string contents(
        std::istreambuf_iterator<char> {input}, std::istreambuf_iterator<char> {}
      );
      if (contents.size() > maximum_environment_size) return {};

      std::map<std::string, std::string> result;
      std::size_t offset = 0;
      while (offset < contents.size()) {
        const auto end = contents.find('\0', offset);
        const auto length = (end == std::string::npos ? contents.size() : end) - offset;
        const std::string_view entry {contents.data() + offset, length};
        const auto separator = entry.find('=');
        if (separator != std::string_view::npos) {
          const auto name = entry.substr(0, separator);
          if (std::ranges::find(allowed, name) != allowed.end()) {
            result.emplace(name, entry.substr(separator + 1));
          }
        }
        if (end == std::string::npos) break;
        offset = end + 1;
      }
      return result;
    }

    template<class Integer>
    std::optional<Integer> parse_integer(std::string_view value) {
      Integer result {};
      const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
      if (value.empty() || parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size()) {
        return std::nullopt;
      }
      return result;
    }

    std::optional<int> inherited_control_descriptor() {
      const char *raw_descriptor = getenv("PLANK_SESSION_CONTROL_FD");
      if (raw_descriptor == nullptr) return std::nullopt;
      const auto descriptor = parse_integer<int>(raw_descriptor);
      if (!descriptor || *descriptor <= STDERR_FILENO) return std::nullopt;
      return descriptor;
    }

    bool root_supervisor_peer(int descriptor) {
      ucred peer {};
      socklen_t peer_size = sizeof(peer);
      return getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) == 0 &&
             peer_size == sizeof(peer) && peer.uid == 0 && peer.pid > 1;
    }

    std::optional<std::string> receive_control_record(int descriptor) {
      std::array<char, maximum_update_size + 1> buffer {};
      const ssize_t size = recv(descriptor, buffer.data(), buffer.size(), MSG_TRUNC);
      if (size <= 0 || static_cast<std::size_t>(size) > maximum_update_size) {
        return std::nullopt;
      }
      return std::string {buffer.data(), static_cast<std::size_t>(size)};
    }

    std::optional<update_t> receive_update(int descriptor) {
      const auto record = receive_control_record(descriptor);
      return record ? parse_session_update(*record) : std::nullopt;
    }

    bool same_active_session(const descriptor_t &candidate) {
      const auto active = active_seat0_graphical_session();
      return active && active->id == candidate.id && active->uid == candidate.uid &&
             active->seat == candidate.seat && active->type == candidate.type &&
             active->session_class == candidate.session_class &&
             eligible_graphical_session(candidate);
    }

    bool valid_optional_audio_paths(const update_t &update) {
      if (update.environment.pulse_server.empty() && update.environment.pulse_cookie.empty()) {
        return true;
      }
      constexpr std::string_view unix_prefix = "unix:";
      if (!update.environment.pulse_server.starts_with(unix_prefix) ||
          update.environment.pulse_cookie.empty()) return false;
      struct stat cookie_status {};
      constexpr std::string_view runtime_cookie =
        "/run/plank/host/pulse-cookie";
      const bool valid_runtime_cookie = update.environment.pulse_cookie == runtime_cookie &&
        lstat(update.environment.pulse_cookie.c_str(), &cookie_status) == 0 &&
        cookie_status.st_uid == 0 && S_ISREG(cookie_status.st_mode) &&
        (cookie_status.st_mode & 0777) == 0600;
      return owned_socket(
               update.environment.pulse_server.substr(unix_prefix.size()), update.session.uid
             ) && valid_runtime_cookie;
    }

    bool valid_update_environment(const update_t &update) {
      static const std::regex local_display {R"(^:[0-9]+(?:\.[0-9]+)?$)"};
      const std::string required_runtime = "/run/user/" + std::to_string(update.session.uid);
      const auto &environment = update.environment;
      if (!std::regex_match(environment.display, local_display) ||
          environment.runtime_directory != required_runtime ||
          !owned_path(environment.runtime_directory, update.session.uid, true) ||
          environment.xauthority.empty() || environment.xauthority.front() != '/' ||
          !owned_path(environment.xauthority, update.session.uid, false)) {
        return false;
      }
      const std::string expected_bus = "unix:path=" + required_runtime + "/bus";
      return (environment.dbus_address.empty() || environment.dbus_address == expected_bus) &&
             valid_optional_audio_paths(update);
    }

    void set_or_unset(const char *name, const std::string &value) {
      if (value.empty()) unsetenv(name);
      else setenv(name, value.c_str(), 1);
    }

    bool accept_update(const update_t &update) {
      if (update.generation == 0 || update.generation <= current_generation.load() ||
          !same_active_session(update.session) || !valid_update_environment(update)) return false;

      set_or_unset("DISPLAY", update.environment.display);
      set_or_unset("XAUTHORITY", update.environment.xauthority);
      set_or_unset("XDG_RUNTIME_DIR", update.environment.runtime_directory);
      set_or_unset("XDG_SESSION_ID", update.session.id);
      set_or_unset("XDG_SESSION_TYPE", update.session.type);
      set_or_unset("XDG_SESSION_CLASS", update.session.session_class);
      set_or_unset("XDG_SEAT", update.session.seat);
      set_or_unset("DBUS_SESSION_BUS_ADDRESS", update.environment.dbus_address);
      set_or_unset("PULSE_SERVER", update.environment.pulse_server);
      set_or_unset("PULSE_COOKIE", update.environment.pulse_cookie);
      {
        std::lock_guard lock {current_update_mutex};
        current_update = update;
      }
      current_generation.store(update.generation, std::memory_order_release);
      return true;
    }

    void acknowledge_update(int descriptor, std::uint64_t generation, bool accepted) {
      const std::string message = "SC-ACK-2\n" + std::to_string(generation) +
                                  (accepted ? "\nOK" : "\nREJECT");
      send(descriptor, message.data(), message.size(), MSG_NOSIGNAL);
    }

    class supervisor_control_impl_t final: public supervisor_control_t {
    public:
      supervisor_control_impl_t(int descriptor, std::function<void(std::uint64_t)> on_reattach,
                                std::function<void()> on_desktop_handoff):
          descriptor_ {descriptor},
          thread_ {[this, callback = std::move(on_reattach),
                    handoff = std::move(on_desktop_handoff)](std::stop_token stop) {
            while (!stop.stop_requested()) {
              const auto record = receive_control_record(descriptor_);
              if (!record) break;
              if (*record == desktop_handoff_command) {
                bool greeter = false;
                {
                  std::lock_guard lock {current_update_mutex};
                  greeter = current_update && current_update->session.session_class == "greeter";
                }
                if (greeter && handoff) handoff();
                continue;
              }
              const auto update = parse_session_update(*record);
              if (!update) break;
              const bool accepted = accept_update(*update);
              acknowledge_update(descriptor_, update->generation, accepted);
              if (accepted) callback(update->generation);
            }
            std::lock_guard lock {current_update_mutex};
            current_update.reset();
          }} {
      }

      ~supervisor_control_impl_t() override {
        {
          std::lock_guard lock {supervisor_descriptor_mutex};
          supervisor_descriptor = -1;
        }
        thread_.request_stop();
        shutdown(descriptor_, SHUT_RDWR);
        if (thread_.joinable()) thread_.join();
        close(descriptor_);
      }

    private:
      int descriptor_ {-1};
      std::jthread thread_;
    };
  }  // namespace

  bool eligible_graphical_session(const descriptor_t &session) {
    return session.active && !session.remote && session.seat == "seat0" &&
           session.type == "x11" && session.state == "active" &&
           (session.session_class == "user" || session.session_class == "greeter");
  }

  std::string_view desktop_stage(const descriptor_t &attached, const descriptor_t &active) {
    if (!eligible_graphical_session(active) || attached.id != active.id ||
        attached.uid != active.uid || attached.session_class != active.session_class) {
      return "unknown";
    }
    return active.session_class == "greeter" ? "greeter" : "user";
  }

  std::string confirmed_desktop_stage() {
    const auto active = active_seat0_graphical_session();
    std::lock_guard lock {current_update_mutex};
    return active && current_update ?
      std::string {desktop_stage(current_update->session, *active)} : "unknown";
  }

  std::optional<descriptor_t> describe(std::string_view session_id) {
    if (session_id.empty() || session_id.find('\0') != std::string_view::npos) return std::nullopt;
    const std::string id {session_id};
    descriptor_t result;
    result.id = id;
    if (sd_session_get_uid(id.c_str(), &result.uid) < 0) return std::nullopt;
    const auto seat = session_string(sd_session_get_seat, id);
    const auto type = session_string(sd_session_get_type, id);
    const auto session_class = session_string(sd_session_get_class, id);
    const auto state = session_string(sd_session_get_state, id);
    if (!seat || !type || !session_class || !state) return std::nullopt;
    result.seat = *seat;
    result.type = *type;
    result.session_class = *session_class;
    result.state = *state;
    const int active = sd_session_is_active(id.c_str());
    const int remote = sd_session_is_remote(id.c_str());
    if (active < 0 || remote < 0) return std::nullopt;
    result.active = active > 0;
    result.remote = remote > 0;
    return result;
  }

  std::optional<descriptor_t> active_seat0_graphical_session() {
    char *raw_session = nullptr;
    uid_t uid {};
    if (sd_seat_get_active("seat0", &raw_session, &uid) < 0 || raw_session == nullptr) {
      return std::nullopt;
    }
    login_string_t session_id {raw_session, &free};
    auto result = describe(session_id.get());
    if (!result || result->uid != uid || !eligible_graphical_session(*result)) return std::nullopt;
    return result;
  }

  std::optional<environment_t> discover_environment(const descriptor_t &session) {
    if (!eligible_graphical_session(session)) return std::nullopt;
    const std::string required_runtime = "/run/user/" + std::to_string(session.uid);
    if (!owned_path(required_runtime, session.uid, true)) return std::nullopt;
    static const std::regex local_display {R"(^:[0-9]+(?:\.[0-9]+)?$)"};

    std::error_code error;
    for (const auto &entry : std::filesystem::directory_iterator("/proc", error)) {
      if (error) break;
      const auto pid = parse_pid(entry.path());
      if (!pid) continue;
      char *raw_session = nullptr;
      if (sd_pid_get_session(*pid, &raw_session) < 0 || raw_session == nullptr) continue;
      login_string_t process_session {raw_session, &free};
      if (session.id != process_session.get()) continue;
      const auto values = read_selected_environment(*pid);
      const auto display = values.find("DISPLAY");
      const auto xauthority = values.find("XAUTHORITY");
      const auto runtime = values.find("XDG_RUNTIME_DIR");
      if (display == values.end() || xauthority == values.end() || runtime == values.end() ||
          !std::regex_match(display->second, local_display) ||
          runtime->second != required_runtime || xauthority->second.empty() ||
          xauthority->second.front() != '/' || !owned_path(xauthority->second, session.uid, false)) {
        continue;
      }
      environment_t result {
        display->second, xauthority->second, runtime->second, {}, {}, {}
      };
      if (const auto dbus = values.find("DBUS_SESSION_BUS_ADDRESS"); dbus != values.end()) {
        result.dbus_address = dbus->second;
      }
      return result;
    }
    return std::nullopt;
  }

  std::string session_update_message(const update_t &update) {
    const std::array<std::string, 15> fields {
      std::to_string(update.generation), update.session.id, std::to_string(update.session.uid),
      update.session.seat, update.session.type, update.session.session_class, update.session.state,
      update.session.active ? "1" : "0", update.session.remote ? "1" : "0",
      update.environment.display, update.environment.xauthority,
      update.environment.runtime_directory, update.environment.dbus_address,
      update.environment.pulse_server, update.environment.pulse_cookie,
    };
    if (update.generation == 0 || !eligible_graphical_session(update.session) ||
        update.session.id.empty() || !std::ranges::all_of(fields, [](const auto &field) {
          return field.find('\0') == std::string::npos;
        })) return {};
    std::string message {update_prefix};
    message.push_back('\0');
    for (const auto &field : fields) {
      message.append(field);
      message.push_back('\0');
    }
    return message.size() <= maximum_update_size ? message : std::string {};
  }

  std::optional<update_t> parse_session_update(std::string_view message) {
    std::vector<std::string_view> fields;
    std::size_t offset = 0;
    while (offset < message.size()) {
      const auto end = message.find('\0', offset);
      if (end == std::string_view::npos) return std::nullopt;
      fields.emplace_back(message.substr(offset, end - offset));
      offset = end + 1;
    }
    if (message.size() > maximum_update_size || fields.size() != 16 ||
        fields.front() != update_prefix) return std::nullopt;
    const auto generation = parse_integer<std::uint64_t>(fields[1]);
    const auto uid = parse_integer<unsigned long long>(fields[3]);
    if (!generation || *generation == 0 || !uid || *uid > std::numeric_limits<uid_t>::max() ||
        (fields[8] != "0" && fields[8] != "1") ||
        (fields[9] != "0" && fields[9] != "1")) return std::nullopt;
    update_t result {
      *generation,
      {
        std::string {fields[2]}, static_cast<uid_t>(*uid), std::string {fields[4]},
        std::string {fields[5]}, std::string {fields[6]}, std::string {fields[7]},
        fields[8] == "1", fields[9] == "1",
      },
      {
        std::string {fields[10]}, std::string {fields[11]}, std::string {fields[12]},
        std::string {fields[13]}, std::string {fields[14]}, std::string {fields[15]},
      },
    };
    return eligible_graphical_session(result.session) ?
             std::optional<update_t> {std::move(result)} : std::nullopt;
  }

  std::string display_request_message(const display_request_t &request) {
    const std::string_view action =
      request.action == display_request_t::action_t::acquire ? "acquire" :
      request.action == display_request_t::action_t::activate ? "activate" :
                                                               "release";
    const bool acquire_valid = request.action != display_request_t::action_t::acquire ||
      ((request.layout == "single" || request.layout == "dual-horizontal") &&
       plank::topology::valid_virtual_layout_modes(
         request.layout, request.mode_1, request.mode_2
       ));
    const bool control_valid = request.action == display_request_t::action_t::acquire ||
      (request.layout.empty() && request.mode_1.empty() && request.mode_2.empty());
    if (!acquire_valid || !control_valid || request.account_uid == 0) {
      return {};
    }
    const auto account_uid = std::to_string(request.account_uid);
    const std::array<std::string_view, 6> fields {
      display_request_prefix, action, request.layout, request.mode_1,
      request.mode_2, account_uid
    };
    std::string message;
    for (const auto field : fields) {
      if (field.find('\0') != std::string_view::npos) return {};
      message.append(field);
      message.push_back('\0');
    }
    return message.size() <= maximum_update_size ? message : std::string {};
  }

  std::optional<display_request_t> parse_display_request(std::string_view message) {
    std::vector<std::string_view> fields;
    std::size_t offset = 0;
    while (offset < message.size()) {
      const auto end = message.find('\0', offset);
      if (end == std::string_view::npos) return std::nullopt;
      fields.emplace_back(message.substr(offset, end - offset));
      offset = end + 1;
    }
    if (message.size() > maximum_update_size || fields.size() != 6 ||
        fields.front() != display_request_prefix) return std::nullopt;
    const auto account_uid = parse_integer<unsigned long long>(fields[5]);
    if (!account_uid || *account_uid == 0 ||
        *account_uid > std::numeric_limits<uid_t>::max()) return std::nullopt;
    const auto action = fields[1] == "acquire" ? display_request_t::action_t::acquire :
      fields[1] == "activate" ? display_request_t::action_t::activate :
      fields[1] == "release" ? display_request_t::action_t::release :
                                display_request_t::action_t {};
    if (fields[1] != "acquire" && fields[1] != "activate" &&
        fields[1] != "release") return std::nullopt;
    display_request_t request {
      action, std::string {fields[2]}, std::string {fields[3]}, std::string {fields[4]},
      static_cast<uid_t>(*account_uid)
    };
    return display_request_message(request).empty() ?
             std::nullopt : std::optional<display_request_t> {std::move(request)};
  }

  std::string runtime_display_state_message(const runtime_display_state_t &state) {
    if ((state.layout != "single" && state.layout != "dual-horizontal") ||
        !plank::topology::valid_virtual_layout_modes(
          state.layout, state.mode_1, state.mode_2
        ) || state.lease_uid == 0) {
      return {};
    }
    const auto lease_uid = std::to_string(state.lease_uid);
    const std::array<std::string_view, 5> fields {
      runtime_display_state_prefix, state.layout, state.mode_1, state.mode_2,
      lease_uid
    };
    std::string message;
    for (const auto field : fields) {
      if (field.find('\0') != std::string_view::npos) return {};
      message.append(field);
      message.push_back('\0');
    }
    return message.size() <= maximum_update_size ? message : std::string {};
  }

  std::optional<runtime_display_state_t> parse_runtime_display_state(
    std::string_view message
  ) {
    std::vector<std::string_view> fields;
    std::size_t offset = 0;
    while (offset < message.size()) {
      const auto end = message.find('\0', offset);
      if (end == std::string_view::npos) return std::nullopt;
      fields.emplace_back(message.substr(offset, end - offset));
      offset = end + 1;
    }
    if (message.size() > maximum_update_size || fields.size() != 5 ||
        fields.front() != runtime_display_state_prefix) return std::nullopt;
    const auto lease_uid = parse_integer<unsigned long long>(fields[4]);
    if (!lease_uid || *lease_uid == 0 ||
        *lease_uid > std::numeric_limits<uid_t>::max()) return std::nullopt;
    runtime_display_state_t state {
      std::string {fields[1]}, std::string {fields[2]}, std::string {fields[3]},
      static_cast<uid_t>(*lease_uid)
    };
    return runtime_display_state_message(state).empty() ?
      std::nullopt : std::optional<runtime_display_state_t> {std::move(state)};
  }

  std::optional<runtime_display_state_t> read_runtime_display_state(
    std::string_view path
  ) {
    struct stat status {};
    const std::string owned_path {path};
    if (lstat(owned_path.c_str(), &status) != 0 || status.st_uid != 0 ||
        !S_ISREG(status.st_mode) || status.st_size <= 0 ||
        status.st_size > static_cast<off_t>(maximum_update_size)) {
      return std::nullopt;
    }
    std::ifstream input {owned_path, std::ios::binary};
    if (!input) return std::nullopt;
    std::string contents(
      std::istreambuf_iterator<char> {input}, std::istreambuf_iterator<char> {}
    );
    return input.bad() ? std::nullopt : parse_runtime_display_state(contents);
  }

  std::optional<bool> secondary_output_visible_from_overlay(std::string_view overlay) {
    constexpr std::string_view marker = "# Generated by PLANK; do not edit.";
    constexpr std::string_view option = "Option \"MetaModes\"";
    if (!overlay.starts_with(marker)) return std::nullopt;
    const auto option_offset = overlay.find(option);
    if (option_offset == std::string_view::npos) return std::nullopt;
    const auto line_end = overlay.find('\n', option_offset);
    const auto line = overlay.substr(
      option_offset,
      line_end == std::string_view::npos ? overlay.size() - option_offset :
                                           line_end - option_offset
    );
    if (line.find("DFP-2: NULL") != std::string_view::npos) return false;
    if (line.find("DFP-2:") != std::string_view::npos) return true;
    return std::nullopt;
  }

  startup_layout_t configured_startup_layout(std::string_view config_path) {
    constexpr std::size_t maximum_config_size = 1024U * 1024U;
    std::ifstream input {std::string {config_path}};
    if (!input) return startup_layout_t::invalid;

    auto trim = [](std::string_view value) {
      constexpr std::string_view whitespace = " \t\r\n";
      const auto first = value.find_first_not_of(whitespace);
      if (first == std::string_view::npos) return std::string_view {};
      const auto last = value.find_last_not_of(whitespace);
      return value.substr(first, last - first + 1);
    };

    bool in_display_section = false;
    bool saw_startup_layout = false;
    startup_layout_t layout = startup_layout_t::physical;
    std::size_t total_size = 0;
    std::string line;
    while (std::getline(input, line)) {
      total_size += line.size() + 1;
      if (total_size > maximum_config_size) return startup_layout_t::invalid;
      const auto text = trim(line);
      if (text.empty() || text.front() == '#' || text.front() == ';') continue;
      if (text.front() == '[') {
        if (text.size() < 2 || text.back() != ']') return startup_layout_t::invalid;
        in_display_section = trim(text.substr(1, text.size() - 2)) == "display";
        continue;
      }
      if (!in_display_section) continue;
      const auto separator = text.find('=');
      if (separator == std::string_view::npos) return startup_layout_t::invalid;
      const auto key = trim(text.substr(0, separator));
      if (key != "startup_layout") continue;
      if (saw_startup_layout) return startup_layout_t::invalid;
      saw_startup_layout = true;
      const auto value = trim(text.substr(separator + 1));
      if (value == "physical") {
        layout = startup_layout_t::physical;
        continue;
      }
      if (value == "virtual") {
        layout = startup_layout_t::virtual_display;
        continue;
      }
      return startup_layout_t::invalid;
    }
    return input.bad() ? startup_layout_t::invalid : layout;
  }

  display_request_status request_display_transition(const display_request_t &request) {
    const std::string message = display_request_message(request);
    if (message.empty()) return display_request_status::invalid;

    std::optional<update_t> attestation;
    {
      std::lock_guard lock {current_update_mutex};
      attestation = current_update;
    }
    if (!attestation) return display_request_status::unavailable;
    const auto active = active_seat0_graphical_session();
    if (!active || active->id != attestation->session.id ||
        active->uid != attestation->session.uid) {
      return display_request_status::unavailable;
    }
    if (active->session_class == "user" && active->uid != request.account_uid) {
      return display_request_status::wrong_user;
    }
    if (active->session_class != "greeter" && active->session_class != "user") {
      return display_request_status::unavailable;
    }

    std::lock_guard lock {supervisor_descriptor_mutex};
    if (supervisor_descriptor < 0 ||
        send(supervisor_descriptor, message.data(), message.size(), MSG_NOSIGNAL) !=
          static_cast<ssize_t>(message.size())) {
      return display_request_status::unavailable;
    }
    return display_request_status::submitted;
  }

  display_request_status activate_display_lease(uid_t account_uid) {
    return request_display_transition({
      display_request_t::action_t::activate, {}, {}, {}, account_uid
    });
  }

  display_request_status release_display_lease(uid_t account_uid) {
    return request_display_transition({
      display_request_t::action_t::release, {}, {}, {}, account_uid
    });
  }

  std::unique_ptr<supervisor_control_t> start_supervisor_control(
    std::function<void(std::uint64_t)> on_reattach,
    std::function<void()> on_desktop_handoff
  ) {
    const auto descriptor = inherited_control_descriptor();
    if (!descriptor || !root_supervisor_peer(*descriptor)) {
      if (descriptor) close(*descriptor);
      return {};
    }
    const auto initial = receive_update(*descriptor);
    if (!initial) {
      close(*descriptor);
      return {};
    }
    const bool accepted = accept_update(*initial);
    acknowledge_update(*descriptor, initial->generation, accepted);
    if (!accepted) {
      close(*descriptor);
      return {};
    }
    {
      std::lock_guard lock {supervisor_descriptor_mutex};
      supervisor_descriptor = *descriptor;
    }
    return std::make_unique<supervisor_control_impl_t>(
      *descriptor, std::move(on_reattach), std::move(on_desktop_handoff));
  }

  bool supervisor_attests_account_for_active_seat0(uid_t account_uid) {
    if (geteuid() != 0 || account_uid == 0) return false;
    std::optional<update_t> attestation;
    {
      std::lock_guard lock {current_update_mutex};
      attestation = current_update;
    }
    if (!attestation) return false;
    const auto active = active_seat0_graphical_session();
    if (!active || active->id != attestation->session.id ||
        active->uid != attestation->session.uid) return false;
    return active->session_class == "greeter" || active->uid == account_uid;
  }

  std::uint64_t desktop_generation() {
    return current_generation.load(std::memory_order_acquire);
  }
}  // namespace plank::session
