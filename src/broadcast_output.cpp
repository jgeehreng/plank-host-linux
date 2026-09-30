/**
 * @file src/broadcast_output.cpp
 * @brief Build and supervise the UltraGrid NDI sender.
 */

#include "broadcast_output.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

namespace plank::broadcast {
  namespace {
    bool token(std::string_view value, std::size_t limit, std::string_view extra) {
      if (value.empty() || value.size() > limit) return false;
      for (const unsigned char ch : value) {
        const bool alnum = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
        if (!alnum && extra.find(static_cast<char>(ch)) == std::string_view::npos) return false;
      }
      return true;
    }

    bool ndi_name_ok(std::string_view name) {
      if (!token(name, 120, " ()._-")) return false;
      return name != "ndi" && name.find(':') == std::string_view::npos;
    }

    bool codec_ok(std::string_view codec) {
      return token(codec, 120, "_.:+=-");
    }

    bool path_ok(std::string_view path) {
      if (path.find('/') == std::string_view::npos) return token(path, 64, "._+-");
      return !path.empty() && path.front() == '/' && token(path, 256, "/._+-");
    }

    bool ipv4_ok(std::string_view address) {
      unsigned parts[4] {};
      std::size_t index = 0;
      std::size_t cursor = 0;
      while (index < 4 && cursor < address.size()) {
        if (address[cursor] < '0' || address[cursor] > '9') return false;
        unsigned value = 0;
        const std::size_t start = cursor;
        while (cursor < address.size() && address[cursor] >= '0' && address[cursor] <= '9') {
          value = value * 10u + static_cast<unsigned>(address[cursor] - '0');
          if (value > 255 || cursor - start > 2) return false;
          ++cursor;
        }
        if (cursor == start || (cursor - start > 1 && address[start] == '0')) return false;
        parts[index++] = value;
        if (index < 4) {
          if (cursor >= address.size() || address[cursor] != '.') return false;
          ++cursor;
        }
      }
      return index == 4 && cursor == address.size();
    }
  }  // namespace

  bool configured(bool enabled, std::string_view ndi_name, std::string_view codec, std::string_view uv_path) {
    return enabled && ndi_name_ok(ndi_name) && codec_ok(codec) && path_ok(uv_path);
  }

  std::string ipv4_text(std::uint32_t value) {
    char text[16];
    const int length = std::snprintf(
      text, sizeof(text), "%u.%u.%u.%u",
      (value >> 24) & 0xffu, (value >> 16) & 0xffu, (value >> 8) & 0xffu, value & 0xffu
    );
    if (length <= 0 || static_cast<std::size_t>(length) >= sizeof(text)) return {};
    return text;
  }

  command_t build(const request_t &request) {
    command_t command;
    if (!request.enabled) {
      command.refusal = "broadcast output is disabled";
      return command;
    }
    if (!ndi_name_ok(request.ndi_name)) {
      command.refusal = "pinned NDI name is missing or unsafe";
      return command;
    }
    if (!codec_ok(request.codec)) {
      command.refusal = "broadcast codec preset is missing or unsafe";
      return command;
    }
    if (!path_ok(request.uv_path)) {
      command.refusal = "broadcast uv path is missing or unsafe";
      return command;
    }
    if (!ipv4_ok(request.peer_ipv4) || request.announced_ipv4 != request.peer_ipv4) {
      command.refusal = "broadcast receive address is not the connected client";
      return command;
    }
    if (request.video_port < 1024 || request.video_port > 65533) {
      command.refusal = "broadcast receive port is out of range";
      return command;
    }
    const unsigned audio = static_cast<unsigned>(request.video_port) + 2u;
    command.argv = {
      std::string(request.uv_path),
      "-t",
      std::string("ndi:name=") + std::string(request.ndi_name),
      "-s",
      "embedded",
      "--audio-codec",
      "OPUS",
      "-c",
      std::string(request.codec),
      "-P",
      "41004:" + std::to_string(request.video_port) + ":41006:" + std::to_string(audio),
      std::string(request.peer_ipv4),
    };
    return command;
  }

  sender_t::~sender_t() {
    stop();
  }

  void sender_t::stop_unlocked() noexcept {
    if (pid_ <= 0) {
      argv_.clear();
      return;
    }
    if (kill(-pid_, SIGTERM) != 0 && errno != ESRCH) {
      kill(pid_, SIGTERM);
    }
    for (int attempt = 0; attempt < 20; ++attempt) {
      int status = 0;
      const pid_t result = waitpid(pid_, &status, WNOHANG);
      if (result == pid_ || (result < 0 && errno == ECHILD)) {
        pid_ = -1;
        argv_.clear();
        return;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    kill(-pid_, SIGKILL);
    kill(pid_, SIGKILL);
    int status = 0;
    waitpid(pid_, &status, 0);
    pid_ = -1;
    argv_.clear();
  }

  void sender_t::stop() noexcept {
    std::lock_guard<std::mutex> guard(mutex_);
    stop_unlocked();
  }

  void sender_t::replace(const command_t &command) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (command.argv.empty()) {
      stop_unlocked();
      return;
    }
    if (pid_ > 0 && command.argv == argv_ && kill(pid_, 0) == 0) return;
    stop_unlocked();

    std::vector<char *> args;
    args.reserve(command.argv.size() + 1);
    for (const std::string &arg : command.argv) args.push_back(const_cast<char *>(arg.c_str()));
    args.push_back(nullptr);

    posix_spawnattr_t attributes;
    if (posix_spawnattr_init(&attributes) != 0) return;
    posix_spawnattr_setpgroup(&attributes, 0);
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
    pid_t child = -1;
    const int result = posix_spawn(&child, command.argv.front().c_str(), nullptr, &attributes, args.data(), environ);
    posix_spawnattr_destroy(&attributes);
    if (result != 0 || child <= 0) return;
    pid_ = child;
    argv_ = command.argv;
  }
}  // namespace plank::broadcast
