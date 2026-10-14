/**
 * @file tests/unit/test_pam_deadlines.cpp
 * @brief Real socket and child-process tests for bounded broker operations.
 */
#include "src/auth/pam_broker_protocol.h"
#include "src/auth/pam_client.h"
#include "src/auth/pam_worker_watch.h"

#include <future>
#include <gtest/gtest.h>

namespace {
  namespace auth = plank::auth;
  using namespace std::chrono_literals;

  /** @brief Socket fixture that closes on assertions/exception paths. */
  class PamDeadline: public testing::Test {
  protected:
    int sockets[2] {-1, -1};  ///< Owned test pair.

    /** @brief Create the pair. */
    void SetUp() override {
      ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets), 0);
    }

    /** @brief Release remaining ends. */
    void TearDown() override {
      for (int fd : sockets) {
        if (fd >= 0) {
          close(fd);
        }
      }
    }

    /** @brief Build an absolute short test budget. @return Deadline context. */
    auth::io_context_t budget() const {
      return {auth::io_context_t::clock_t::now() + 100ms, {}};
    }
  };
}  // namespace

TEST_F(PamDeadline, SilentPeerTimesOut) {
  auth::message_t message;
  auto context = budget();
  EXPECT_FALSE(auth::read_message(sockets[0], message, context));
  EXPECT_EQ(errno, ETIMEDOUT);
  EXPECT_LT(auth::io_context_t::clock_t::now(), context.deadline + 500ms);
}

TEST_F(PamDeadline, HeaderAndBodyShareOneAbsoluteDeadline) {
  const auth::io_context_t context {auth::io_context_t::clock_t::now() + 500ms, {}};
  auto wire = auth::encode_message({auth::message_type_e::result, 1, {1, 2}});
  // Send the header just before the operation deadline, then stall the body.
  auto writer = std::async(std::launch::async, [&]() {
    std::this_thread::sleep_for(300ms);
    return auth::write_all(sockets[1], std::span {wire}.first(sizeof(auth::wire_header_t)));
  });
  auth::message_t message;
  EXPECT_FALSE(auth::read_message(sockets[0], message, context));
  EXPECT_EQ(errno, ETIMEDOUT);
  EXPECT_LT(auth::io_context_t::clock_t::now(), context.deadline + 150ms);
  EXPECT_TRUE(writer.get());
}

TEST_F(PamDeadline, FullSendBufferTimesOutForSensitiveWrite) {
  const int small = 1024;
  ASSERT_EQ(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)), 0);
  std::array<char, 4096> fill {};
  while (send(sockets[0], fill.data(), fill.size(), MSG_DONTWAIT | MSG_NOSIGNAL) > 0) {}
  ASSERT_EQ(errno, EAGAIN);
  auto context = budget();
  EXPECT_FALSE(auth::write_sensitive_message(sockets[0], {auth::message_type_e::response, 1, {1, 2, 3}}, context));
  EXPECT_EQ(errno, ETIMEDOUT);
  EXPECT_LT(auth::io_context_t::clock_t::now(), context.deadline + 500ms);
}

TEST_F(PamDeadline, CancellationInterruptsReadAndClosesBrokerChannel) {
  auto client = auth::pam_client_t::adopt_for_test(std::exchange(sockets[0], -1), 1, 2s);
  auto reader = std::async(std::launch::async, [&]() {
    return client.read_step_for_test();
  });
  client.cancel();
  EXPECT_EQ(reader.wait_for(500ms), std::future_status::ready);
  EXPECT_EQ(reader.get().state, auth::step_t::state_e::denied);
  EXPECT_FALSE(client.connected());
  char byte;
  EXPECT_EQ(recv(sockets[1], &byte, 1, MSG_DONTWAIT), 0);
}

TEST_F(PamDeadline, ClientTimeoutClosesChannelWithoutWaitingForPAM) {
  auto client = auth::pam_client_t::adopt_for_test(std::exchange(sockets[0], -1), 1, 100ms);
  EXPECT_EQ(client.read_step_for_test().state, auth::step_t::state_e::denied);
  EXPECT_FALSE(client.connected());
  char byte;
  EXPECT_EQ(recv(sockets[1], &byte, 1, MSG_DONTWAIT), 0);
}

TEST_F(PamDeadline, CloseNeverWritesToUnresponsiveBroker) {
  auto client = auth::pam_client_t::adopt_for_test(std::exchange(sockets[0], -1), 1, 2s);
  const auto before = auth::io_context_t::clock_t::now();
  client.close();
  EXPECT_LT(auth::io_context_t::clock_t::now() - before, 100ms);
}

TEST_F(PamDeadline, InfiniteSessionBudgetDoesNotUseAuthenticationDeadline) {
  const auth::io_context_t session {auth::io_context_t::clock_t::time_point::max(), {}};
  EXPECT_EQ(session.remaining_ms(60000), 60000);
  ASSERT_TRUE(auth::write_message(sockets[1], {auth::message_type_e::cancel, 1, {}}));
  auth::message_t message;
  EXPECT_TRUE(auth::read_message(sockets[0], message, session));
}

TEST_F(PamDeadline, WorkerLivesWhileConnectedButIsReapedAfterAbandonment) {
  auth::pam_workers_t workers {50ms};
  auto pid = fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    close(sockets[1]);  // Do not keep the caller's end alive.
    // Simulates a PAM module that neither notices EOF nor honors SIGTERM.
    signal(SIGTERM, SIG_IGN);
    for (;;) {
      pause();
    }
  }
  workers.add(pid, std::exchange(sockets[0], -1));
  for (int i = 0; i < 15; ++i) {
    workers.maintain();
    poll(nullptr, 0, 10);
  }
  EXPECT_EQ(workers.size(), 1);
  EXPECT_EQ(kill(pid, 0), 0);
  close(std::exchange(sockets[1], -1));
  const auto deadline = auth::io_context_t::clock_t::now() + 1s;
  while (workers.size() && auth::io_context_t::clock_t::now() < deadline) {
    workers.maintain();
    poll(nullptr, 0, 10);
  }
  EXPECT_EQ(workers.size(), 0);
  EXPECT_EQ(waitpid(pid, nullptr, WNOHANG), -1);
  EXPECT_EQ(errno, ECHILD);
}

TEST_F(PamDeadline, WorkerShutdownIsBoundedEvenIfPAMNeverReturns) {
  auth::pam_workers_t workers {50ms};
  auto pid = fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    close(sockets[1]);
    signal(SIGTERM, SIG_IGN);
    for (;;) {
      pause();
    }
  }
  workers.add(pid, std::exchange(sockets[0], -1));
  const auto before = auth::io_context_t::clock_t::now();
  workers.stop();
  EXPECT_LT(auth::io_context_t::clock_t::now() - before, 500ms);
  EXPECT_EQ(workers.size(), 0);
  EXPECT_EQ(waitpid(pid, nullptr, WNOHANG), -1);
  EXPECT_EQ(errno, ECHILD);
}
