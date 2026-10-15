/**
 * @file src/auth/admission_networks.h
 * @brief Uppercut: networks where a broker admission is not required.
 *
 * `admission_exempt_networks` lists office networks, for example
 * "192.168.76.0/24, 10.20.0.0/16". A client connecting from one of them may
 * sign in without a broker admission, like a direct PCoIP connection on the
 * office network. An admission that is presented is still verified. Anything
 * that does not parse exempts nothing.
 */
#pragma once

#include <boost/asio/ip/address.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace plank::admission {

  struct network_t {
    std::array<std::uint8_t, 16> bytes {};  ///< Network address (IPv4 uses the first 4 bytes).
    bool v6 = false;
    int prefix = 0;
  };

  inline std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    return text;
  }

  /** Parse one "address/prefix" (or a bare address, meaning one host). */
  inline std::optional<network_t> parse_network(std::string_view text) {
    text = trim(text);
    const auto slash = text.find('/');
    const std::string address_text {text.substr(0, slash)};
    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(address_text, error);
    if (error) return std::nullopt;
    network_t network;
    network.v6 = address.is_v6();
    const int max_prefix = network.v6 ? 128 : 32;
    network.prefix = max_prefix;
    if (slash != std::string_view::npos) {
      const auto digits = text.substr(slash + 1);
      if (digits.empty() || digits.size() > 3) return std::nullopt;
      int prefix = 0;
      for (const char c : digits) {
        if (c < '0' || c > '9') return std::nullopt;
        prefix = prefix * 10 + (c - '0');
      }
      if (prefix > max_prefix) return std::nullopt;
      network.prefix = prefix;
    }
    if (network.v6) {
      const auto raw = address.to_v6().to_bytes();
      std::copy(raw.begin(), raw.end(), network.bytes.begin());
    } else {
      const auto raw = address.to_v4().to_bytes();
      std::copy(raw.begin(), raw.end(), network.bytes.begin());
    }
    return network;
  }

  /**
   * Parse a comma-separated list. Returns nullopt if any entry is malformed,
   * so a typo never silently widens or narrows the exemption.
   */
  inline std::optional<std::vector<network_t>> parse_networks(std::string_view text) {
    std::vector<network_t> networks;
    while (!trim(text).empty()) {
      const auto comma = text.find(',');
      const auto entry = text.substr(0, comma);
      if (!trim(entry).empty()) {
        const auto network = parse_network(entry);
        if (!network) return std::nullopt;
        networks.push_back(*network);
      }
      if (comma == std::string_view::npos) break;
      text.remove_prefix(comma + 1);
    }
    return networks;
  }

  inline bool contains(const network_t &network, const boost::asio::ip::address &input) {
    auto address = input;
    if (address.is_v6() && address.to_v6().is_v4_mapped()) {
      address = boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped, address.to_v6());
    }
    if (address.is_v6() != network.v6) return false;
    std::array<std::uint8_t, 16> bytes {};
    if (address.is_v6()) {
      const auto raw = address.to_v6().to_bytes();
      std::copy(raw.begin(), raw.end(), bytes.begin());
    } else {
      const auto raw = address.to_v4().to_bytes();
      std::copy(raw.begin(), raw.end(), bytes.begin());
    }
    int remaining = network.prefix;
    for (std::size_t i = 0; remaining > 0; ++i, remaining -= 8) {
      const std::uint8_t mask = remaining >= 8 ? 0xff : static_cast<std::uint8_t>(0xff << (8 - remaining));
      if ((bytes[i] & mask) != (network.bytes[i] & mask)) return false;
    }
    return true;
  }

  /** True when peer (a normalized address string) is inside a configured network. */
  inline bool exempt(std::string_view configured, std::string_view peer) {
    const auto networks = parse_networks(configured);
    if (!networks || networks->empty()) return false;
    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(std::string {peer}, error);
    if (error) return false;
    for (const auto &network : *networks) {
      if (contains(network, address)) return true;
    }
    return false;
  }

}  // namespace plank::admission
