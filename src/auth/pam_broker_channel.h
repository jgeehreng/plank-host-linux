/**
 * @file src/auth/pam_broker_channel.h
 * @brief Private supervisor delegation of connected PAM sockets, never credentials.
 */
#pragma once

#include "pam_broker_protocol.h"

#include <array>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace plank::auth::broker_channel {
  constexpr char environment_name[] = "PLANK_PAM_CHANNEL_FD";  ///< Inherited private channel.
  constexpr char broker_path[] = "/run/plank/pam/auth.sock";  ///< Only delegatable endpoint.
  constexpr char request_byte = 'P';  ///< One version-1 connect request, no caller data.

  /**
   * @brief Verify a connected socket's type and root peer.
   * @param fd Socket to inspect.
   * @param type Required socket type.
   * @param parent Whether the peer must be this worker's parent supervisor.
   * @return Whether credentials and type match the required endpoint.
   */
  inline bool trusted_peer(int fd, int type, bool parent = false) {
    int actual_type = 0;
    socklen_t size = sizeof(actual_type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &actual_type, &size) != 0 || size != sizeof(actual_type) || actual_type != type) {
      return false;
    }
    ucred peer {};
    size = sizeof(peer);
    return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 &&
           size == sizeof(peer) && peer.uid == 0 && peer.pid > 1 &&
           (!parent || peer.pid == getppid());
  }

  /**
   * @brief Get the root-created inherited channel without opening any filesystem path.
   * @return Valid private descriptor, or -1.
   */
  inline int inherited_descriptor() {
    const char *raw = std::getenv(environment_name);
    if (!raw) {
      return -1;
    }
    int fd = -1;
    const auto end = raw + std::strlen(raw);
    const auto parsed = std::from_chars(raw, end, fd);
    if (parsed.ec != std::errc {} || parsed.ptr != end || fd <= STDERR_FILENO || !trusted_peer(fd, SOCK_SEQPACKET, true)) {
      return -1;
    }
    const int flags = fcntl(fd, F_GETFD);
    return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0 ? fd : -1;
  }

  /**
   * @brief Receive exactly one bounded record and at most one delegated descriptor.
   * @param channel Connected private sequenced-packet channel.
   * @param byte Expected single-byte record. 'O' also accepts an 'E' denial without an FD.
   * @param needs_fd Whether exactly one descriptor is required for success.
   * @param fd Receives ownership on success, otherwise remains -1.
   * @return False on truncation, malformed ancillary data, EOF or error.
   */
  inline bool receive_record(int channel, char byte, bool needs_fd, int &fd) {
    fd = -1;
    char payload[2] {};
    iovec data {payload, sizeof(payload)};
    alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(int) * 8)> control {};
    msghdr message {};
    message.msg_iov = &data;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    const auto count = recvmsg(channel, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    if (count < 0) {
      return false;
    }
    const bool denied = byte == 'O' && payload[0] == 'E';
    bool valid = count == 1 && (payload[0] == byte || denied) &&
                 (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0;
    unsigned int received = 0;
    for (auto *entry = CMSG_FIRSTHDR(&message); entry;
         entry = CMSG_NXTHDR(&message, entry)) {
      if (entry->cmsg_level != SOL_SOCKET || entry->cmsg_type != SCM_RIGHTS || entry->cmsg_len < CMSG_LEN(0)) {
        valid = false;
        continue;
      }
      const auto bytes = entry->cmsg_len - CMSG_LEN(0);
      if (bytes % sizeof(int) != 0) {
        valid = false;
      }
      for (std::size_t offset = 0; offset + sizeof(int) <= bytes; offset += sizeof(int)) {
        int candidate = -1;
        std::memcpy(&candidate, CMSG_DATA(entry) + offset, sizeof(candidate));
        if (received++ == 0) {
          fd = candidate;
        } else {
          close(candidate);
        }
      }
    }
    valid = valid && received == (needs_fd && !denied ? 1U : 0U);
    if (!valid && fd >= 0) {
      close(fd);
      fd = -1;
    }
    return valid;
  }

  /**
   * @brief Send a successful delegation or a descriptor-free denial without blocking.
   * @param channel Private channel.
   * @param fd Connected broker descriptor, or -1 for denial; ownership is retained.
   * @return Whether the complete record was queued.
   */
  inline bool send_connection(int channel, int fd) {
    char response = fd >= 0 ? 'O' : 'E';
    iovec data {&response, sizeof(response)};
    alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(int))> control {};
    msghdr message {};
    message.msg_iov = &data;
    message.msg_iovlen = 1;
    if (fd >= 0) {
      message.msg_control = control.data();
      message.msg_controllen = control.size();
      auto *entry = CMSG_FIRSTHDR(&message);
      entry->cmsg_level = SOL_SOCKET;
      entry->cmsg_type = SCM_RIGHTS;
      entry->cmsg_len = CMSG_LEN(sizeof(fd));
      std::memcpy(CMSG_DATA(entry), &fd, sizeof(fd));
    }
    return sendmsg(channel, &message, MSG_NOSIGNAL | MSG_DONTWAIT) == 1;
  }

  /**
   * @brief Connect only to the fixed root-owned broker; backlog exhaustion fails closed.
   * @return Owned connected descriptor, or -1. Called only by the supervisor.
   */
  inline int connect_broker() {
    struct stat metadata {};
    if (lstat(broker_path, &metadata) != 0 || !S_ISSOCK(metadata.st_mode) || metadata.st_uid != 0 || (metadata.st_mode & 0777) != 0600) {
      return -1;
    }
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
      return -1;
    }
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, broker_path, sizeof(broker_path));
    // AF_UNIX returns EAGAIN when its backlog is full. Do not let a wedged PAM
    // listener stall display/session supervision or pretend it is connected.
    if (connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 || !trusted_peer(fd, SOCK_STREAM) || fcntl(fd, F_SETFL, 0) != 0) {
      close(fd);
      return -1;
    }
    return fd;
  }

  /**
   * @brief Request a broker connection, serializing the descriptor-only exchange.
   * @param context Deadline/cancellation including the wait for serialization.
   * @return Owned root-broker socket, or -1. No direct-connect fallback exists.
   */
  inline int request_connection(io_context_t context = {}) {
    static std::timed_mutex request_mutex;
    std::unique_lock lock {request_mutex, std::defer_lock};
    while (!lock.owns_lock()) {
      const int remaining = context.remaining_ms(25);
      if (remaining == 0) {
        return -1;
      }
      if (lock.try_lock_for(std::chrono::milliseconds {remaining})) {
        break;
      }
    }
    if (context.remaining_ms() == 0) {
      return -1;
    }
    const int channel = inherited_descriptor();
    if (channel < 0) {
      return -1;
    }
    context.deadline = std::min(context.deadline, io_context_t::clock_t::now() + std::chrono::seconds {3});
    // Once submitted, drain this exact reply even if cancellation is requested.
    // The bounded descriptor handshake must not poison subsequent logins or
    // let a later caller consume this request's delegated descriptor.
    const io_context_t handshake {context.deadline, {}};
    int result = -1;
    if (send(channel, &request_byte, 1, MSG_NOSIGNAL | MSG_DONTWAIT) == 1 && wait_ready(channel, POLLIN, handshake) && receive_record(channel, 'O', true, result) && (result < 0 || trusted_peer(result, SOCK_STREAM))) {
      if (context.remaining_ms() == 0) {
        if (result >= 0) {
          close(result);
        }
        return -1;
      }
      return result;
    }
    if (result >= 0) {
      close(result);
    }
    // Never consume a late reply as the result of a later request. Replacing
    // this worker creates a fresh channel; there is no fallback to root paths.
    shutdown(channel, SHUT_RDWR);
    return -1;
  }
}  // namespace plank::auth::broker_channel
