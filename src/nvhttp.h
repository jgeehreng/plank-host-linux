/**
 * @file src/nvhttp.h
 * @brief Declarations for the PLANK session-negotiation server.
 */
#pragma once

#include <fcntl.h>
#include <mutex>
#include <Simple-Web-Server/server_https.hpp>
#include <stdexcept>

namespace nvhttp {

  constexpr auto VERSION = "7.1.431.-1";
  constexpr auto GFE_VERSION = "3.23.0.74";
  constexpr auto PORT_HTTPS = 0;

  /**
   * @brief Start the PLANK authentication and session-negotiation server.
   */
  void start();

  /**
   * @brief Simple-Web-Server HTTPS transport used by PLANK.
   */
  class SunshineHTTPS: public SimpleWeb::HTTPS {
  public:
    SunshineHTTPS(boost::asio::io_context &io_context, boost::asio::ssl::context &ctx):
        SimpleWeb::HTTPS(io_context, ctx) {
    }

    virtual ~SunshineHTTPS() {
      SimpleWeb::error_code ec;
      shutdown(ec);
    }
  };

  /**
   * @brief HTTPS server backend that requires TLS 1.3.
   */
  class SunshineHTTPSServer: public SimpleWeb::ServerBase<SunshineHTTPS> {
  public:
    /**
     * @brief Initialize the HTTPS server with Sunshine's certificate and key files.
     *
     * @param certification_file Path to the server certificate file.
     * @param private_key_file Path to the matching private key file.
     * @param tls13_only Require the product's TLS 1.3 minimum.
     */
    SunshineHTTPSServer(const std::string &certification_file, const std::string &private_key_file, bool tls13_only):
        ServerBase<SunshineHTTPS>::ServerBase(443),
        context(boost::asio::ssl::context::tls_server) {
      // Disabling TLS 1.0 and 1.1 (see RFC 8996)
      context.set_options(boost::asio::ssl::context::no_tlsv1);
      context.set_options(boost::asio::ssl::context::no_tlsv1_1);
      if (tls13_only && SSL_CTX_set_min_proto_version(context.native_handle(), TLS1_3_VERSION) != 1) {
        throw std::runtime_error("Unable to require TLS 1.3 for PLANK authentication");
      }
      context.use_certificate_chain_file(certification_file);
      context.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);
    }

    /**
     * @brief Duplicate the request's TCP socket solely for disconnect monitoring.
     * @param request Request being dispatched on the HTTPS event loop.
     * @return Owned CLOEXEC descriptor, or -1 when the connection has gone away.
     */
    int duplicate_auth_peer(const std::shared_ptr<Request> &request) {
      const auto peer = request->remote_endpoint();
      const auto local = request->local_endpoint();
      std::lock_guard lock {connections->mutex};
      for (auto *connection : connections->set) {
        SimpleWeb::error_code ec;
        auto &socket = connection->socket->lowest_layer();
        const auto endpoint = socket.remote_endpoint(ec);
        if (!ec && endpoint == peer && socket.local_endpoint(ec) == local && !ec) {
          return fcntl(socket.native_handle(), F_DUPFD_CLOEXEC, 0);
        }
      }
      return -1;
    }

  protected:
    boost::asio::ssl::context context;  ///< TLS server context configured with Sunshine's certificate and protocol policy.

    // This is Server<HTTPS>::accept() with SSL validation support added
    /**
     * @brief Accept a pending connection and arm the server for the next client.
     */
    void accept() override {
      auto connection = create_connection(*io_service, context);

      acceptor->async_accept(connection->socket->lowest_layer(), [this, connection](const SimpleWeb::error_code &ec) {
        auto lock = connection->handler_runner->continue_lock();
        if (!lock) {
          return;
        }

        if (ec != SimpleWeb::error::operation_aborted) {
          this->accept();
        }

        auto session = std::make_shared<Session>(config.max_request_streambuf_size, connection);

        if (!ec) {
          boost::asio::ip::tcp::no_delay option(true);
          SimpleWeb::error_code ec;
          session->connection->socket->lowest_layer().set_option(option, ec);

          session->connection->set_timeout(config.timeout_request);
          session->connection->socket->async_handshake(boost::asio::ssl::stream_base::server, [this, session](const SimpleWeb::error_code &ec) {
            session->connection->cancel_timeout();
            auto lock = session->connection->handler_runner->continue_lock();
            if (!lock) {
              return;
            }
            if (!ec) {
              this->read(session);
            } else if (this->on_error) {
              this->on_error(session->request, ec);
            }
          });
        } else if (this->on_error) {
          this->on_error(session->request, ec);
        }
      });
    }
  };

}  // namespace nvhttp
