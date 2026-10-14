/**
 * @file src/raw_hid_feedback.h
 * @brief Ordered, bounded forwarding of reliable tablet control messages.
 */
#pragma once

#include <optional>
#include <utility>
#include <plank_transport.h>
#include "raw_hid_tablet.h"

namespace raw_hid {
  /**
   * @brief Drain at most eight messages without losing one on backpressure.
   * @param queue Bounded reliable producer queue.
   * @param pending Message owned by this consumer until transport acceptance.
   * @param send Transport sender returning OK, TIMEOUT (retry) or an error.
   * @return OK/TIMEOUT, or an error requiring session input cleanup.
   */
  template<class Sender>
  int drain_feedback(feedback_queue_t &queue, std::optional<std::vector<std::uint8_t>> &pending, Sender &&send) {
    if (!queue->running()) {
      return PLANK_TRANSPORT_ERROR_INVALID_STATE;
    }
    for (unsigned count = 0; count < 8; ++count) {
      if (!pending) {
        auto frame = queue->pop(std::chrono::milliseconds(0));
        if (!frame) {
          break;
        }
        pending = std::move(*frame);
      }
      const auto result = send(*pending);
      if (result != PLANK_TRANSPORT_OK) {
        return result;
      }
      pending.reset();
    }
    return PLANK_TRANSPORT_OK;
  }
}  // namespace raw_hid
