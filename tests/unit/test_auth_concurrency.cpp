/**
 * @file tests/unit/test_auth_concurrency.cpp
 * @brief Exercise authentication isolation, late results, admission and shutdown.
 */
#include "src/auth/auth_executor.h"
#include "src/auth/web_auth.h"

#include <atomic>
#include <condition_variable>
#include <fcntl.h>
#include <future>
#include <gtest/gtest.h>
#include <sys/socket.h>

namespace {
  namespace auth = plank::auth;
  using namespace std::chrono_literals;

  /** @brief Controllable slow backend; bounded even when the regression under test returns. */
  struct backend_t {
    std::mutex mutex;
    std::condition_variable changed;
    bool entered = false;
    bool released = false;
    bool block_begin = false;
    bool block_response = false;
    bool ignore_cancel = false;
    std::atomic_int cancellations {0};
    std::function<void()> on_destroy;

    /** @brief Wait for a simulated backend call to enter. @return True when entered. */
    bool wait() {
      std::unique_lock lock {mutex};
      return changed.wait_for(lock, 1s, [&]() {
        return entered;
      });
    }

    /** @brief Unblock the backend. */
    void release() {
      std::lock_guard lock {mutex};
      released = true;
      changed.notify_all();
    }

    /** @brief Simulate a blocking backend without letting a failed test hang forever. */
    void block() {
      std::unique_lock lock {mutex};
      entered = true;
      changed.notify_all();
      changed.wait_for(lock, 2s, [&]() {
        return released;
      });
    }
  };

  /** @brief A backend that may report success even after cancellation. */
  class conversation_t: public auth::conversation_i {
  public:
    /** @brief Attach test state. @param state Shared backend controls. */
    explicit conversation_t(std::shared_ptr<backend_t> state):
        state_ {std::move(state)} {}

    /** @brief Observe where teardown runs. */
    ~conversation_t() override {
      if (state_->on_destroy) {
        state_->on_destroy();
      }
    }

    /** @brief Return a prompt, optionally after blocking. */
    auth::step_t begin(std::uint64_t, std::string_view, std::string_view) override {
      if (state_->block_begin) {
        state_->block();
      }
      return {auth::step_t::state_e::challenge, {{1, "Password:"}}, auth::phase_e::authenticate, 0};
    }

    /** @brief Return success, including deliberately late results. */
    auth::step_t respond(std::vector<std::string>) override {
      if (state_->block_response) {
        state_->block();
      }
      return {auth::step_t::state_e::authenticated, {}, auth::phase_e::authenticated, 0};
    }

    /** @brief Request cancellation without waiting for the backend. */
    void cancel() noexcept override {
      ++state_->cancellations;
      if (!state_->ignore_cancel) {
        state_->release();
      }
    }

  private:
    std::shared_ptr<backend_t> state_;  ///< Shared simulation state.
  };
}  // namespace

TEST(AuthConcurrency, StalledBeginDoesNotBlockTokensClaimsOrOtherLogins) {
  auto fast = std::make_shared<backend_t>();
  auto slow = std::make_shared<backend_t>();
  slow->block_begin = true;
  int factories = 0;
  int ids = 0;
  auth::web_auth_manager_t manager {
    [&]() {
      return std::make_unique<conversation_t>(++factories == 2 ? slow : fast);
    },
    [&](std::size_t) {
      return std::to_string(++ids);
    },
  };
  auto prompt = manager.begin("user", "peer");
  auto token = manager.respond(prompt.conversation_id, "peer", {"test"}).session_token;
  auto blocked = std::async(std::launch::async, [&]() {
    return manager.begin("user", "peer");
  });
  ASSERT_TRUE(slow->wait());
  const auto before = std::chrono::steady_clock::now();
  EXPECT_TRUE(manager.identity(token, "peer"));
  auto live = manager.claim(token, "peer");
  EXPECT_TRUE(live);
  EXPECT_EQ(manager.begin("user", "other-peer").state, auth::step_t::state_e::challenge);
  manager.cancel(token);
  manager.cancel_all();
  EXPECT_LT(std::chrono::steady_clock::now() - before, 500ms);
  EXPECT_EQ(blocked.get().state, auth::step_t::state_e::denied);
  // Revoking a claimed token must not stop its live stream/PAM owner.
  EXPECT_EQ(fast->cancellations.load(), 1);  // Only the unclaimed third conversation.
}

TEST(AuthConcurrency, DuplicateResponseRejectedAndCancellationDiscardsLateSuccess) {
  auto backend = std::make_shared<backend_t>();
  backend->block_response = true;
  backend->ignore_cancel = true;
  int ids = 0;
  auth::web_auth_manager_t manager {
    [backend]() {
      return std::make_unique<conversation_t>(backend);
    },
    [&](std::size_t) {
      return std::to_string(++ids);
    },
  };
  auto id = manager.begin("user", "peer").conversation_id;
  auto blocked = std::async(std::launch::async, [&]() {
    return manager.respond(id, "peer", {"test"});
  });
  ASSERT_TRUE(backend->wait());
  auto before = std::chrono::steady_clock::now();
  EXPECT_EQ(manager.respond(id, "peer", {"duplicate"}).state, auth::step_t::state_e::denied);
  manager.cancel(id);
  EXPECT_LT(std::chrono::steady_clock::now() - before, 500ms);
  backend->release();
  auto result = blocked.get();
  EXPECT_EQ(result.state, auth::step_t::state_e::denied);
  EXPECT_TRUE(result.session_token.empty());
  EXPECT_EQ(ids, 1);  // No token minted after cancellation.
}

TEST(AuthConcurrency, ExpiredInFlightResponseCannotPublishToken) {
  auto backend = std::make_shared<backend_t>();
  backend->block_response = true;
  std::atomic_int seconds {0};
  int ids = 0;
  auth::web_auth_manager_t manager {
    [backend]() {
      return std::make_unique<conversation_t>(backend);
    },
    [&](std::size_t) {
      return std::to_string(++ids);
    },
    [&]() {
      return auth::web_auth_manager_t::clock_t::time_point {} + std::chrono::seconds {seconds.load()};
    },
    1s,
  };
  auto id = manager.begin("user", "peer").conversation_id;
  auto blocked = std::async(std::launch::async, [&]() {
    return manager.respond(id, "peer", {"test"});
  });
  ASSERT_TRUE(backend->wait());
  seconds = 2;
  manager.expire();
  EXPECT_EQ(blocked.get().state, auth::step_t::state_e::denied);
  EXPECT_EQ(ids, 1);
}

TEST(AuthConcurrency, CancelledInflightWorkStillConsumesCapacity) {
  auto slow = std::make_shared<backend_t>();
  slow->block_begin = true;
  slow->ignore_cancel = true;
  auto fast = std::make_shared<backend_t>();
  int factories = 0;
  int ids = 0;
  auth::web_auth_manager_t manager {
    [&]() {
      return std::make_unique<conversation_t>(++factories == 1 ? slow : fast);
    },
    [&](std::size_t) {
      return std::to_string(++ids);
    },
  };
  auto blocked = std::async(std::launch::async, [&]() {
    return manager.begin("user", "peer");
  });
  ASSERT_TRUE(slow->wait());
  manager.cancel("1");
  for (int i = 0; i < 31; ++i) {
    EXPECT_EQ(manager.begin("user", "peer").state, auth::step_t::state_e::challenge);
  }
  EXPECT_EQ(manager.begin("user", "peer").state, auth::step_t::state_e::denied);
  EXPECT_EQ(factories, 32);
  slow->release();
  EXPECT_EQ(blocked.get().state, auth::step_t::state_e::denied);
  EXPECT_EQ(manager.begin("user", "peer").state, auth::step_t::state_e::challenge);
}

TEST(AuthConcurrency, TeardownRunsOutsideManagerLock) {
  auto backend = std::make_shared<backend_t>();
  auth::web_auth_manager_t manager {
    [backend]() {
      return std::make_unique<conversation_t>(backend);
    },
    [](std::size_t) {
      return "conversation";
    },
  };
  auto id = manager.begin("user", "peer").conversation_id;
  std::atomic_bool observed {false};
  backend->on_destroy = [&]() {
    observed = !manager.authorize("missing", "peer");
  };
  manager.cancel(id);
  EXPECT_TRUE(observed);
}

TEST(AuthConcurrency, RequestOwnerCancellationStopsBackend) {
  auto backend = std::make_shared<backend_t>();
  backend->block_begin = true;
  auth::web_auth_manager_t manager {
    [backend]() {
      return std::make_unique<conversation_t>(backend);
    },
    [](std::size_t) {
      return "conversation";
    },
  };
  std::stop_source owner;
  auto blocked = std::async(std::launch::async, [&]() {
    return manager.begin("user", "peer", owner.get_token());
  });
  ASSERT_TRUE(backend->wait());
  owner.request_stop();
  EXPECT_EQ(blocked.wait_for(500ms), std::future_status::ready);
  EXPECT_EQ(blocked.get().state, auth::step_t::state_e::denied);
}

TEST(AuthExecutor, BoundsAdmissionAndCancelsAllWorkersAtShutdown) {
  auth::auth_executor_t executor;
  std::atomic_int entered {0};
  std::atomic_int cancelled {0};
  for (int i = 0; i < 4; ++i) {
    EXPECT_TRUE(executor.submit([&](std::stop_token stop) {
      ++entered;
      std::mutex mutex;
      std::condition_variable_any ready;
      std::unique_lock lock {mutex};
      ready.wait_for(lock, stop, 2s, []() {
        return false;
      });
      if (stop.stop_requested()) {
        ++cancelled;
      }
    }));
  }
  EXPECT_FALSE(executor.submit([](std::stop_token) {
  }));
  executor.stop();
  EXPECT_EQ(entered.load(), 4);
  EXPECT_EQ(cancelled.load(), 4);
  EXPECT_FALSE(executor.submit([](std::stop_token) {
  }));
}

TEST(AuthExecutor, PeerAbortCancelsOnlyItsOwnAuthentication) {
  auth::auth_executor_t executor;
  auto backend = std::make_shared<backend_t>();
  backend->block_begin = true;
  auth::web_auth_manager_t manager {
    [backend]() {
      return std::make_unique<conversation_t>(backend);
    },
    [](std::size_t) {
      return "conversation";
    },
  };
  int pair[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair), 0);
  // The executor owns a duplicate, so closing/reusing the server's original
  // handle cannot make its peer monitor inspect some unrelated connection.
  const int watched = fcntl(pair[0], F_DUPFD_CLOEXEC, 0);
  ASSERT_GE(watched, 0);
  std::promise<auth::web_auth_step_t> completed;
  auto result = completed.get_future();
  EXPECT_TRUE(executor.submit([&](std::stop_token stop) {
    completed.set_value(manager.begin("user", "peer", stop));
  },
                              watched));
  EXPECT_TRUE(backend->wait());
  EXPECT_EQ(result.wait_for(30ms), std::future_status::timeout);
  std::atomic_bool other_cancelled {false};
  EXPECT_TRUE(executor.submit([&](std::stop_token stop) {
    std::mutex mutex;
    std::condition_variable_any ready;
    std::unique_lock lock {mutex};
    ready.wait_for(lock, stop, 2s, []() {
      return false;
    });
    other_cancelled = stop.stop_requested();
  }));
  close(pair[0]);
  const int unrelated = open("/dev/null", O_RDONLY | O_CLOEXEC);
  EXPECT_GE(unrelated, 0);
  close(pair[1]);  // Equivalent to the Client aborting its HTTPS request.
  EXPECT_EQ(result.wait_for(500ms), std::future_status::ready);
  EXPECT_EQ(result.get().state, auth::step_t::state_e::denied);
  EXPECT_FALSE(other_cancelled);
  executor.stop();
  EXPECT_TRUE(other_cancelled);
  EXPECT_NE(fcntl(unrelated, F_GETFD), -1);
  close(unrelated);
}

TEST(AuthExecutor, SuccessfulJobsAndBusyRejectionReleaseWatchDescriptors) {
  auth::auth_executor_t executor;
  int pair[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair), 0);
  std::promise<void> completed;
  auto result = completed.get_future();
  const int watched = fcntl(pair[0], F_DUPFD_CLOEXEC, 0);
  EXPECT_TRUE(executor.submit([&](std::stop_token stop) {
    EXPECT_FALSE(stop.stop_requested());
    completed.set_value();
  },
                              watched));
  EXPECT_EQ(result.wait_for(500ms), std::future_status::ready);
  executor.stop();
  EXPECT_EQ(fcntl(watched, F_GETFD), -1);
  EXPECT_EQ(errno, EBADF);
  const int rejected = fcntl(pair[0], F_DUPFD_CLOEXEC, 0);
  EXPECT_FALSE(executor.submit([](std::stop_token) {
  },
                               rejected));
  EXPECT_EQ(fcntl(rejected, F_GETFD), -1);
  EXPECT_EQ(errno, EBADF);
  close(pair[0]);
  close(pair[1]);
}
