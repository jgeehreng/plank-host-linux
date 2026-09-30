/**
 * @file src/broadcast_output.h
 * @brief Point-to-point UltraGrid sender command for a pinned NDI source.
 */
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace plank::broadcast {
  /**
   * @brief argv for one `uv` sender. Empty when the request must not run.
   */
  struct command_t {
    std::vector<std::string> argv;  ///< Executable and arguments, never a shell line.
    std::string refusal;  ///< Why argv is empty. Empty when argv is usable.
  };

  /**
   * @brief Inputs for one sender command. The client may supply only the address and port.
   */
  struct request_t {
    bool enabled = false;  ///< Host `broadcast_output` switch.
    std::string_view uv_path;  ///< UltraGrid executable. Not taken from the client.
    std::string_view ndi_name;  ///< Pinned NDI source name. Not taken from the client.
    std::string_view codec;  ///< Administrator codec preset. Not taken from the client.
    std::string_view peer_ipv4;  ///< IPv4 of the connected PLANK client.
    std::string_view announced_ipv4;  ///< IPv4 the client asked to receive on.
    std::uint16_t video_port = 0;  ///< Client UDP video receive port. Audio is this plus 2.
  };

  /**
   * @brief Whether a host configuration can advertise a broadcast source.
   *
   * @param enabled `broadcast_output`.
   * @param ndi_name Pinned NDI source name.
   * @param codec Administrator codec preset.
   * @param uv_path UltraGrid executable.
   * @return True when a later session may start `uv` for this host.
   */
  bool configured(bool enabled, std::string_view ndi_name, std::string_view codec, std::string_view uv_path);

  /**
   * @brief Build the sender argv. The only session-specific field is the client address and port.
   *
   * A bare `ndi` capture, a different NDI name, and a client-supplied codec are rejected.
   *
   * @param request Host configuration plus the connected client's receive endpoint.
   * @return Command whose argv is empty when the request is refused.
   */
  command_t build(const request_t &request);

  /**
   * @brief Format a big-endian IPv4 word as dotted decimal.
   *
   * @param value Address with the first octet in the high byte.
   * @return Dotted decimal, or an empty string when formatting fails.
   */
  std::string ipv4_text(std::uint32_t value);

  /**
   * @brief One UltraGrid sender process owned by a PLANK session.
   */
  class sender_t {
  public:
    sender_t() = default;
    sender_t(const sender_t &) = delete;
    sender_t &operator=(const sender_t &) = delete;
    ~sender_t();

    /**
     * @brief Replace any running sender with this command.
     *
     * @param command Command from build(). An empty argv stops the sender.
     */
    void replace(const command_t &command);

    /**
     * @brief Stop the sender if it is running.
     */
    void stop() noexcept;

  private:
    void stop_unlocked() noexcept;

    int pid_ = -1;  ///< Child process id, or -1.
    std::vector<std::string> argv_;  ///< Command currently running.
    std::mutex mutex_;  ///< Serializes start and stop.
  };
}  // namespace plank::broadcast
