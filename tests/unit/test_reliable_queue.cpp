/**
 * @file tests/unit/test_reliable_queue.cpp
 * @brief Reliable tablet feedback must retain order through bounded pressure.
 */
#include <future>
#include <gtest/gtest.h>
#include "src/thread_safe.h"
#include "src/raw_hid_feedback.h"

using namespace std::chrono_literals;

TEST(ReliableQueue, FullQueueRetainsAllPredecessors) {
  safe::queue_t<int> queue {2};
  ASSERT_TRUE(queue.raise_reliable(1, 0ms));
  ASSERT_TRUE(queue.raise_reliable(2, 0ms));
  EXPECT_FALSE(queue.raise_reliable(3, 1ms));
  EXPECT_EQ(*queue.pop(0ms), 1);
  EXPECT_EQ(*queue.pop(0ms), 2);
  EXPECT_FALSE(queue.pop(0ms));
}

TEST(ReliableQueue, ConsumerMakesSpaceAndStopWakesProducer) {
  safe::queue_t<int> queue {1};
  ASSERT_TRUE(queue.raise_reliable(1, 0ms));
  auto pending = std::async(std::launch::async, [&] { return queue.raise_reliable(2, 2s); });
  EXPECT_EQ(*queue.pop(0ms), 1);
  ASSERT_EQ(pending.wait_for(500ms), std::future_status::ready);
  EXPECT_TRUE(pending.get());
  auto stopped = std::async(std::launch::async, [&] { return queue.raise_reliable(3, 2s); });
  queue.stop();
  ASSERT_EQ(stopped.wait_for(500ms), std::future_status::ready);
  EXPECT_FALSE(stopped.get());
}

TEST(ReliableQueue, TabletFeedbackRetriesTheSameMessageBeforeItsSuccessor) {
  raw_hid::feedback_queue_t queue = std::make_shared<raw_hid::feedback_queue_t::element_type>(std::make_shared<safe::mail_raw_t>(), 2);
  std::optional<std::vector<std::uint8_t>> pending;
  ASSERT_TRUE(queue->raise_reliable({1}, 0ms));
  ASSERT_TRUE(queue->raise_reliable({2}, 0ms));
  unsigned attempts = 0;
  for (int i = 0; i < 20; ++i) {
    EXPECT_EQ(raw_hid::drain_feedback(queue, pending, [&](const auto &frame) {
      EXPECT_EQ(frame, (std::vector<std::uint8_t> {1}));
      ++attempts;
      return PLANK_TRANSPORT_TIMEOUT;
    }), PLANK_TRANSPORT_TIMEOUT);
  }
  EXPECT_EQ(attempts, 20);
  std::vector<unsigned> delivered;
  EXPECT_EQ(raw_hid::drain_feedback(queue, pending, [&](const auto &frame) {
    delivered.push_back(frame[0]);
    return PLANK_TRANSPORT_OK;
  }), PLANK_TRANSPORT_OK);
  EXPECT_EQ(delivered, (std::vector<unsigned> {1, 2}));
  EXPECT_FALSE(pending);
  queue->stop();
  EXPECT_EQ(raw_hid::drain_feedback(queue, pending, [&](const auto &) {
    ADD_FAILURE() << "Stopped queues must not send";
    return PLANK_TRANSPORT_OK;
  }), PLANK_TRANSPORT_ERROR_INVALID_STATE);
}
