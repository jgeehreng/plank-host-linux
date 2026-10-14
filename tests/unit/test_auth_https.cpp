/**
 * @file tests/unit/test_auth_https.cpp
 * @brief Real HTTPS responsiveness and disconnect cancellation, using the product server.
 */
#include "src/auth/auth_executor.h"
#include "src/auth/web_auth.h"
#include "src/nvhttp.h"

#include <condition_variable>
#include <future>
#include <gtest/gtest.h>

namespace {
  namespace auth = plank::auth;
  using namespace std::chrono_literals;

  /** @brief A deliberately silent backend, released by cancellation. */
  struct slow_state_t {
    std::mutex mutex;  ///< Guards test synchronization.
    std::condition_variable changed;  ///< Entry/cancel notification.
    bool entered = false;  ///< PAM operation started.
    bool cancelled = false;  ///< Owner canceled it.
  };

  /** @brief Exercise the real manager while substituting only the external PAM backend. */
  class slow_conversation_t: public auth::conversation_i {
  public:
    /** @brief Retain test controls. @param state Shared state. */
    explicit slow_conversation_t(std::shared_ptr<slow_state_t> state):
        state_ {std::move(state)} {}

    /** @brief Stall until cancellation, bounded on test failures. */
    auth::step_t begin(std::uint64_t, std::string_view, std::string_view) override {
      std::unique_lock lock {state_->mutex};
      state_->entered = true;
      state_->changed.notify_all();
      state_->changed.wait_for(lock, 3s, [&]() {
        return state_->cancelled;
      });
      return {auth::step_t::state_e::denied, {}};
    }

    /** @brief Unused response path. */
    auth::step_t respond(std::vector<std::string>) override {
      return {auth::step_t::state_e::denied, {}};
    }

    /** @brief Observe cancellation. */
    void cancel() noexcept override {
      std::lock_guard lock {state_->mutex};
      state_->cancelled = true;
      state_->changed.notify_all();
    }

  private:
    std::shared_ptr<slow_state_t> state_;  ///< Test controls.
  };

  /** @brief TLS client; accepts only the ephemeral test certificate for this loopback fixture. */
  class client_t {
  public:
    boost::asio::io_context io;  ///< Client event context.
    boost::asio::ssl::context context {boost::asio::ssl::context::tls_client};  ///< Test TLS settings.
    SimpleWeb::HTTPS socket {io, context};  ///< Connected TLS socket.

    /** @brief Connect over loopback TLS. @param port Ephemeral test port. */
    explicit client_t(unsigned short port) {
      context.set_verify_mode(boost::asio::ssl::verify_none);
      socket.lowest_layer().connect({boost::asio::ip::make_address("127.0.0.1"), port});
      socket.handshake(boost::asio::ssl::stream_base::client);
    }

    /** @brief Abort like a timed-out network request, without waiting for TLS shutdown. */
    ~client_t() {
      abort();
    }

    /** @brief Close both TCP directions. */
    void abort() {
      SimpleWeb::error_code ec;
      socket.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
      socket.lowest_layer().close(ec);
    }

    /** @brief Send one request. @param path Request path. */
    void request(std::string_view path) {
      const std::string request = "GET " + std::string(path) + " HTTP/1.1\r\nHost: auth-test.invalid\r\n\r\n";
      boost::asio::write(socket, boost::asio::buffer(request));
    }

    /** @brief Read the response header. @return Received header. */
    std::string header() {
      boost::asio::streambuf buffer;
      boost::asio::read_until(socket, buffer, "\r\n\r\n");
      std::istream input {&buffer};
      return std::string {std::istreambuf_iterator<char>(input), {}};
    }
  };

  /** @brief Server lifecycle identical to production shutdown ordering. */
  class AuthHttps: public testing::Test {
  protected:
    std::unique_ptr<nvhttp::SunshineHTTPSServer> server;  ///< Product HTTPS implementation.
    auth::auth_executor_t executor;  ///< Product bounded worker/cancellation pool.
    std::jthread network;  ///< Sole HTTPS event thread.

    /** @brief Load an ephemeral test identity; no provisioned Host identity is used. */
    void SetUp() override {
      const char *certificate = std::getenv("PLANK_TEST_TLS_CERT");
      const char *key = std::getenv("PLANK_TEST_TLS_KEY");
      if (!certificate || !key) {
        GTEST_SKIP() << "Run the isolated pam-https CTest certificate fixture";
      }
      server = std::make_unique<nvhttp::SunshineHTTPSServer>(certificate, key, true);
      server->config.address = "127.0.0.1";
      server->config.port = 0;
    }

    /** @brief Stop admission before canceling/joining work. */
    void TearDown() override {
      if (server) {
        server->stop();
      }
      if (network.joinable()) {
        network.join();
      }
      executor.stop();
    }

    /** @brief Start the listener. @return Ephemeral port. */
    unsigned short start() {
      auto port = std::make_shared<std::promise<unsigned short>>();
      auto result = port->get_future();
      network = std::jthread {[this, port]() {
        server->start([port](unsigned short value) {
          port->set_value(value);
        });
      }};
      return result.get();
    }
  };
}  // namespace

TEST_F(AuthHttps, StatusWorksWhilePAMStallsAndClientAbortCancelsItsRequest) {
  auto state = std::make_shared<slow_state_t>();
  auto manager = std::make_shared<auth::web_auth_manager_t>(
    [state]() {
      return std::make_unique<slow_conversation_t>(state);
    },
    [](std::size_t) {
      return "test-conversation";
    }
  );
  auto completed = std::make_shared<std::promise<auth::web_auth_step_t>>();
  auto result = completed->get_future();
  server->resource["^/slow$"]["GET"] = [this, manager, completed](auto response, auto request) {
    const int fd = server->duplicate_auth_peer(request);
    EXPECT_GE(fd, 0);
    if (fd < 0) {
      return;
    }
    EXPECT_TRUE(executor.submit([manager, response, completed](std::stop_token stop) {
      completed->set_value(manager->begin("test-user", "loopback", stop));
      response->write("done");
      response->close_connection_after_response = true;
    },
                                fd));
  };
  server->resource["^/status$"]["GET"] = [](auto response, auto) {
    response->write("ready");
    response->close_connection_after_response = true;
  };
  const auto port = start();
  client_t slow {port};
  slow.request("/slow");
  {
    std::unique_lock lock {state->mutex};
    ASSERT_TRUE(state->changed.wait_for(lock, 1s, [&]() {
      return state->entered;
    }));
  }
  const auto before = std::chrono::steady_clock::now();
  {
    client_t status {port};
    status.request("/status");
    EXPECT_NE(status.header().find("200 OK"), std::string::npos);
  }
  EXPECT_LT(std::chrono::steady_clock::now() - before, 500ms);
  slow.abort();
  EXPECT_EQ(result.wait_for(500ms), std::future_status::ready);
  EXPECT_EQ(result.get().state, auth::step_t::state_e::denied);
  std::lock_guard lock {state->mutex};
  EXPECT_TRUE(state->cancelled);
}
