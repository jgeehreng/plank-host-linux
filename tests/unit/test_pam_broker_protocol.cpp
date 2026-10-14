#include <array>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/auth/pam_broker_protocol.h"
#include "src/auth/pam_client.h"

namespace auth = plank::auth;

TEST(PamBrokerProtocol, RoundTripsBoundedMessage) {
  std::vector<std::uint8_t> payload;
  ASSERT_TRUE(auth::append_string(payload, "test-user"));
  ASSERT_TRUE(auth::append_string(payload, "198.51.100.250"));
  ASSERT_TRUE(auth::append_string(payload, "plank"));
  const auth::message_t original {
    auth::message_type_e::begin,
    42,
    payload,
  };

  const auto frame = auth::encode_message(original);
  ASSERT_FALSE(frame.empty());
  auth::message_t decoded;
  ASSERT_TRUE(auth::decode_message(frame, decoded));
  EXPECT_EQ(decoded.type, original.type);
  EXPECT_EQ(decoded.transaction_id, original.transaction_id);

  std::size_t offset = 0;
  std::string username;
  std::string remote_host;
  std::string tty;
  EXPECT_TRUE(auth::read_string(decoded.payload, offset, username));
  EXPECT_TRUE(auth::read_string(decoded.payload, offset, remote_host));
  EXPECT_TRUE(auth::read_string(decoded.payload, offset, tty));
  EXPECT_EQ(offset, decoded.payload.size());
  EXPECT_EQ(username, "test-user");
  EXPECT_EQ(remote_host, "198.51.100.250");
  EXPECT_EQ(tty, "plank");
}

TEST(PamBrokerProtocol, RejectsMalformedAndOversizeFrames) {
  auth::message_t message {
    auth::message_type_e::cancel,
    7,
    {},
  };
  auto frame = auth::encode_message(message);
  ASSERT_EQ(frame.size(), sizeof(auth::wire_header_t));

  auth::message_t decoded;
  EXPECT_FALSE(auth::decode_message(std::span {frame}.first(frame.size() - 1), decoded));

  auto *header = reinterpret_cast<auth::wire_header_t *>(frame.data());
  header->magic = 0;
  EXPECT_FALSE(auth::decode_message(frame, decoded));

  message.transaction_id = 0;
  EXPECT_TRUE(auth::encode_message(message).empty());
  message.transaction_id = 7;
  message.payload.resize(auth::maximum_payload_size + 1);
  EXPECT_TRUE(auth::encode_message(message).empty());

  std::vector<std::uint8_t> fields;
  EXPECT_FALSE(auth::append_string(fields, std::string(auth::maximum_field_size + 1, 'x')));
}

TEST(PamBrokerProtocol, RoundTripsEmptyAndMaximumPayloads) {
  for (const auto size : {std::size_t {0}, std::size_t {1}, auth::maximum_payload_size}) {
    const auth::message_t original {
      auth::message_type_e::result,
      42,
      std::vector<std::uint8_t>(size, 0xa5),
    };
    const auto frame = auth::encode_message(original);
    ASSERT_EQ(frame.size(), sizeof(auth::wire_header_t) + size);
    auth::message_t decoded;
    ASSERT_TRUE(auth::decode_message(frame, decoded));
    EXPECT_EQ(decoded.payload, original.payload);
    EXPECT_EQ(decoded.type, original.type);
    EXPECT_EQ(decoded.transaction_id, original.transaction_id);
  }
}

TEST(PamBrokerProtocol, ReadsAndWritesStreamFrames) {
  std::array<int, 2> sockets {};
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets.data()), 0);
  const auth::message_t original {
    auth::message_type_e::result,
    91,
    {1, 2, 3, 4},
  };
  ASSERT_TRUE(auth::write_message(sockets[0], original));

  auth::message_t decoded;
  ASSERT_TRUE(auth::read_message(sockets[1], decoded));
  EXPECT_EQ(decoded.type, original.type);
  EXPECT_EQ(decoded.transaction_id, original.transaction_id);
  EXPECT_EQ(decoded.payload, original.payload);
  close(sockets[0]);
  close(sockets[1]);
}

TEST(PamBrokerProtocol, ClosedPeerDoesNotRaiseSigpipe) {
  int sockets[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets), 0);
  close(sockets[1]);

  EXPECT_FALSE(auth::write_message(sockets[0], {
    auth::message_type_e::cancel,
    42,
    {},
  }));
  close(sockets[0]);
}

TEST(PamBrokerProtocol, RejectsEmbeddedNulString) {
  std::vector<std::uint8_t> payload;
  ASSERT_TRUE(auth::append_string(payload, std::string_view {"a\0b", 3}));
  std::size_t offset = 0;
  std::string decoded;
  EXPECT_FALSE(auth::read_string(payload, offset, decoded));
}

TEST(PamBrokerClient, AdvancesChallengeAndSuccess) {
  std::array<int, 2> sockets {};
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets.data()), 0);
  constexpr std::uint64_t transaction_id = 1234;
  auto client = auth::pam_client_t::adopt_for_test(sockets[0], transaction_id);

  std::vector<std::uint8_t> challenge;
  auth::append_integer(challenge, static_cast<std::uint32_t>(1));
  auth::append_integer(challenge, static_cast<std::int32_t>(1));
  ASSERT_TRUE(auth::append_string(challenge, "Password: "));
  ASSERT_TRUE(auth::write_message(sockets[1], {
    auth::message_type_e::challenge,
    transaction_id,
    std::move(challenge),
  }));

  const auto prompt = client.read_step_for_test();
  ASSERT_EQ(prompt.state, auth::step_t::state_e::challenge);
  ASSERT_EQ(prompt.prompts.size(), 1);
  EXPECT_EQ(prompt.prompts.front().style, 1);
  EXPECT_EQ(prompt.prompts.front().text, "Password: ");

  std::thread responder {[&]() {
    auth::message_t response;
    ASSERT_TRUE(auth::read_message(sockets[1], response));
    EXPECT_EQ(response.type, auth::message_type_e::response);
    EXPECT_EQ(response.transaction_id, transaction_id);
    std::size_t offset = 0;
    std::uint32_t count = 0;
    std::string secret;
    EXPECT_TRUE(auth::read_integer(response.payload, offset, count));
    EXPECT_EQ(count, 1);
    EXPECT_TRUE(auth::read_string(response.payload, offset, secret));
    EXPECT_EQ(secret, "secret");

    std::vector<std::uint8_t> result;
    auth::append_integer(result, static_cast<std::uint16_t>(auth::phase_e::authenticated));
    auth::append_integer(result, static_cast<std::int32_t>(0));
    ASSERT_TRUE(auth::write_message(sockets[1], {
      auth::message_type_e::result,
      transaction_id,
      std::move(result),
    }));
  }};
  const auto success = client.respond({"secret"});
  responder.join();
  EXPECT_EQ(success.state, auth::step_t::state_e::authenticated);
  EXPECT_TRUE(client.connected());
  client.close();
  close(sockets[1]);
}
