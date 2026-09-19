/**
 * @file src/session/gdm_login.cpp
 * @brief Ask the privileged GDM helper to start a user desktop after PAM.
 */
#include "gdm_login.h"

#include "session_context.h"
#include "../logging.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using namespace std::literals;

namespace plank::session {
  namespace {
    constexpr auto helper_timeout = std::chrono::seconds {25};

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
     * @brief Write an entire buffer or fail.
     *
     * @param descriptor Connected helper socket.
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
     * @brief Read an entire buffer or fail.
     *
     * @param descriptor Connected helper socket.
     * @param data Destination.
     * @param size Byte count.
     * @return True when every byte was read.
     */
    bool read_fully(int descriptor, void *data, std::size_t size) {
      auto *bytes = static_cast<std::uint8_t *>(data);
      std::size_t offset = 0;
      while (offset < size) {
        pollfd wait {descriptor, POLLIN, 0};
        const int ready = poll(
          &wait,
          1,
          static_cast<int>(std::chrono::milliseconds {helper_timeout}.count())
        );
        if (ready <= 0) {
          return false;
        }
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
     * @brief Append a bounded length-prefixed string.
     *
     * @param payload Destination.
     * @param value String to append.
     * @param maximum Maximum accepted size.
     * @return True when the value is in range.
     */
    bool append_field(std::vector<std::uint8_t> &payload, std::string_view value, std::size_t maximum) {
      if (value.size() > maximum || value.size() > 0xffffU) {
        return false;
      }
      const auto size = static_cast<std::uint16_t>(value.size());
      payload.push_back(static_cast<std::uint8_t>(size & 0xffU));
      payload.push_back(static_cast<std::uint8_t>((size >> 8) & 0xffU));
      payload.insert(payload.end(), value.begin(), value.end());
      return true;
    }

    /**
     * @brief Send one GDM login request and read the helper's step byte.
     *
     * @param username PAM account.
     * @param session_id Active greeter logind session.
     * @param secrets PAM responses.
     * @return Helper result, or helper_unavailable on IPC failure.
     */
    gdm_login_step ask_helper(
      std::string_view username,
      std::string_view session_id,
      const std::vector<std::string> &secrets
    ) {
      const int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (descriptor < 0) {
        return gdm_login_step::helper_unavailable;
      }
      sockaddr_un address {};
      address.sun_family = AF_UNIX;
      const auto path = gdm_login_socket_path;
      if (path.size() >= sizeof(address.sun_path)) {
        close(descriptor);
        return gdm_login_step::helper_unavailable;
      }
      std::memcpy(address.sun_path, path.data(), path.size());
      if (connect(
            descriptor,
            reinterpret_cast<const sockaddr *>(&address),
            sizeof(address)
          ) != 0) {
        close(descriptor);
        return gdm_login_step::helper_unavailable;
      }

      std::vector<std::uint8_t> payload {1};
      if (!append_field(payload, username, maximum_gdm_username) ||
          !append_field(payload, session_id, maximum_gdm_session_id) ||
          secrets.size() > maximum_gdm_secrets) {
        close(descriptor);
        return gdm_login_step::helper_unavailable;
      }
      payload.push_back(static_cast<std::uint8_t>(secrets.size()));
      for (const auto &secret : secrets) {
        if (!append_field(payload, secret, maximum_gdm_secret)) {
          close(descriptor);
          return gdm_login_step::helper_unavailable;
        }
      }
      const auto length = static_cast<std::uint32_t>(payload.size());
      std::array<std::uint8_t, 4> prefix {
        static_cast<std::uint8_t>(length & 0xffU),
        static_cast<std::uint8_t>((length >> 8) & 0xffU),
        static_cast<std::uint8_t>((length >> 16) & 0xffU),
        static_cast<std::uint8_t>((length >> 24) & 0xffU)
      };
      const bool sent = write_fully(descriptor, prefix.data(), prefix.size()) &&
                        write_fully(descriptor, payload.data(), payload.size());
      if (!payload.empty()) {
        explicit_bzero(payload.data(), payload.size());
      }
      unsigned char byte = 0;
      const bool got = sent && read_fully(descriptor, &byte, 1);
      close(descriptor);
      if (!got || byte == 0) {
        return gdm_login_step::helper_unavailable;
      }
      return static_cast<gdm_login_step>(byte);
    }
  }  // namespace

  bool complete_gdm_login(std::string_view username, std::vector<std::string> &secrets) {
    struct wiper_t {
      std::vector<std::string> *secrets;
      ~wiper_t() {
        if (secrets != nullptr) {
          wipe(*secrets);
        }
      }
    } wiper {&secrets};

    if (!valid_gdm_username(username) || secrets.empty() || secrets.size() > maximum_gdm_secrets) {
      return false;
    }
    for (const auto &secret : secrets) {
      if (secret.empty() || secret.size() > maximum_gdm_secret ||
          secret.find('\0') != std::string::npos) {
        return false;
      }
    }
    if (geteuid() != 0) {
      return false;
    }
    const auto greeter = active_seat0_graphical_session();
    if (!greeter || greeter->session_class != "greeter" ||
        greeter->id.empty() || greeter->id.size() > maximum_gdm_session_id) {
      return false;
    }

    const auto step = ask_helper(username, greeter->id, secrets);
    if (step == gdm_login_step::ok) {
      BOOST_LOG(info) << "GDM accepted the authenticated user session"sv;
      return true;
    }
    switch (step) {
    case gdm_login_step::join_failed:
      BOOST_LOG(warning) << "GDM login helper could not join the greeter session after PAM"sv;
      break;
    case gdm_login_step::open_session_failed:
      BOOST_LOG(warning) << "GDM OpenSession failed after PAM"sv;
      break;
    case gdm_login_step::connect_failed:
      BOOST_LOG(warning) << "GDM private session connect failed after PAM"sv;
      break;
    case gdm_login_step::begin_failed:
      BOOST_LOG(warning) << "GDM BeginVerificationForUser failed after PAM"sv;
      break;
    case gdm_login_step::verify_timeout:
      BOOST_LOG(warning) << "GDM UserVerifier timed out after PAM"sv;
      break;
    case gdm_login_step::verify_failed:
      BOOST_LOG(warning) << "GDM UserVerifier rejected the conversation after PAM"sv;
      break;
    case gdm_login_step::start_failed:
      BOOST_LOG(warning) << "GDM StartSessionWhenReady failed after PAM"sv;
      break;
    case gdm_login_step::no_gdm_account:
      BOOST_LOG(warning) << "GDM greeter account is unavailable after PAM"sv;
      break;
    case gdm_login_step::helper_unavailable:
      BOOST_LOG(warning) << "GDM login helper is unavailable after PAM"sv;
      break;
    default:
      BOOST_LOG(warning) << "GDM did not start a user session after PAM"sv;
      break;
    }
    return false;
  }
}  // namespace plank::session
