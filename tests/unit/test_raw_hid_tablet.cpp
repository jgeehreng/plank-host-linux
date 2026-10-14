#include <cstring>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

extern "C" {
#include <moonlight-common-c/src/plank.h>
}

#include "src/raw_hid_tablet.h"
#include "src/utility.h"

namespace {
  std::vector<std::uint8_t> make_frame(
    const PLANK_RAW_HID_MESSAGE_TYPE type,
    const std::uint16_t interface_id,
    const std::uint16_t generation,
    const void *payload,
    const std::size_t payload_size
  ) {
    std::vector<std::uint8_t> frame(sizeof(PLANK_RAW_HID_WIRE_HEADER) + payload_size);
    PLANK_RAW_HID_WIRE_HEADER header {};
    header.magic = util::endian::little(static_cast<std::uint32_t>(PLANK_RAW_HID_WIRE_MAGIC));
    header.version = util::endian::little(static_cast<std::uint16_t>(PLANK_RAW_HID_WIRE_VERSION));
    header.type = util::endian::little(static_cast<std::uint16_t>(type));
    header.interfaceId = util::endian::little(interface_id);
    header.generation = util::endian::little(generation);
    header.payloadLength = util::endian::little(static_cast<std::uint32_t>(payload_size));
    std::memcpy(frame.data(), &header, sizeof(header));
    if (payload_size != 0) {
      std::memcpy(frame.data() + sizeof(header), payload, payload_size);
    }
    return frame;
  }
}  // namespace

TEST(RawHidTablet, RejectsMalformedTransportFrames) {
  const auto mail = std::make_shared<safe::mail_raw_t>();
  raw_hid::tablet_t tablet {mail->queue<std::vector<std::uint8_t>>("raw-hid-test")};

  EXPECT_FALSE(tablet.handle({}));

  auto frame = make_frame(PLANK_RAW_HID_DETACH, 0, 1, nullptr, 0);
  reinterpret_cast<PLANK_RAW_HID_WIRE_HEADER *>(frame.data())->magic = 0;
  EXPECT_FALSE(tablet.handle(frame));

  frame = make_frame(PLANK_RAW_HID_DETACH, 0, 1, nullptr, 0);
  reinterpret_cast<PLANK_RAW_HID_WIRE_HEADER *>(frame.data())->payloadLength = util::endian::little<std::uint32_t>(1);
  EXPECT_FALSE(tablet.handle(frame));

  frame = make_frame(PLANK_RAW_HID_DETACH, 0, 1, nullptr, 0);
  reinterpret_cast<PLANK_RAW_HID_WIRE_HEADER *>(frame.data())->version =
    util::endian::little<std::uint16_t>(PLANK_RAW_HID_WIRE_VERSION - 1);
  EXPECT_FALSE(tablet.handle(frame));
}

TEST(RawHidTablet, EnforcesGenerationAndInterfaceBounds) {
  const auto mail = std::make_shared<safe::mail_raw_t>();
  raw_hid::tablet_t tablet {mail->queue<std::vector<std::uint8_t>>("raw-hid-test")};
  PLANK_RAW_HID_DEVICE_MESSAGE device {};
  device.interfaceCount = util::endian::little<std::uint16_t>(2);
  device.bus = util::endian::little<std::uint16_t>(3);
  device.vendor = util::endian::little<std::uint32_t>(0x056a);
  device.product = util::endian::little<std::uint32_t>(0x0357);

  EXPECT_TRUE(tablet.handle(make_frame(
    PLANK_RAW_HID_DEVICE,
    0,
    7,
    &device,
    sizeof(device)
  )));

  const std::uint8_t descriptor[] {0x05, 0x0d, 0x09, 0x02};
  EXPECT_FALSE(tablet.handle(make_frame(
    PLANK_RAW_HID_DESCRIPTOR,
    2,
    7,
    descriptor,
    sizeof(descriptor)
  )));
  EXPECT_FALSE(tablet.handle(make_frame(
    PLANK_RAW_HID_DESCRIPTOR,
    0,
    8,
    descriptor,
    sizeof(descriptor)
  )));
  EXPECT_TRUE(tablet.handle(make_frame(
    PLANK_RAW_HID_DESCRIPTOR,
    0,
    7,
    descriptor,
    sizeof(descriptor)
  )));
  EXPECT_FALSE(tablet.handle(make_frame(
    PLANK_RAW_HID_DESCRIPTOR,
    0,
    7,
    descriptor,
    sizeof(descriptor)
  )));
}

TEST(RawHidTablet, ReusesIdenticalEndpointsAcrossFocusAndTransportResume) {
  if (!raw_hid::available()) {
    GTEST_SKIP() << "/dev/uhid is unavailable to the test process";
  }

  const auto first_mail = std::make_shared<safe::mail_raw_t>();
  raw_hid::tablet_t tablet {first_mail->queue<std::vector<std::uint8_t>>("raw-hid-test")};
  // This empty collection tests UHID lifecycle, not evdev contacts. It has no
  // input node to inspect; contact syscall behavior has its own fixtures.
  tablet.set_contact_cleanup_for_test([] {
    return true;
  });
  PLANK_RAW_HID_DEVICE_MESSAGE device {};
  device.interfaceCount = util::endian::little<std::uint16_t>(1);
  device.bus = util::endian::little<std::uint16_t>(3);
  device.vendor = util::endian::little<std::uint32_t>(0x056a);
  device.product = util::endian::little<std::uint32_t>(0x0358);
  std::memcpy(device.name, "PLANK Wacom test", sizeof("PLANK Wacom test"));
  std::memcpy(device.unique, "stable-tablet", 13);

  // Minimal valid HID application collection. Reuse requires the kernel's
  // UHID_START acknowledgement, not just successful endpoint creation.
  const std::uint8_t descriptor[] {
    0x05, 0x01,  // Usage Page (Generic Desktop)
    0x09, 0x02,  // Usage (Mouse)
    0xa1, 0x01,  // Collection (Application)
    0xc0,  // End Collection
  };

  ASSERT_TRUE(tablet.handle(make_frame(PLANK_RAW_HID_DEVICE, 0, 7, &device, sizeof(device))));
  ASSERT_TRUE(tablet.handle(make_frame(PLANK_RAW_HID_DESCRIPTOR, 0, 7, descriptor, sizeof(descriptor))));
  const auto initial_epoch = tablet.endpoint_epoch();
  ASSERT_GT(initial_epoch, 0);

  const auto attached = first_mail->queue<std::vector<std::uint8_t>>("raw-hid-test")->pop(std::chrono::seconds(5));
  ASSERT_TRUE(attached) << "Kernel did not finish starting the test endpoint";
  ASSERT_GE(attached->size(), sizeof(PLANK_RAW_HID_WIRE_HEADER) + sizeof(std::int32_t));
  PLANK_RAW_HID_WIRE_HEADER ack {};
  std::memcpy(&ack, attached->data(), sizeof(ack));
  ASSERT_EQ(util::endian::little(ack.type), PLANK_RAW_HID_ATTACH_RESULT);
  std::int32_t status;
  std::memcpy(&status, attached->data() + sizeof(ack), sizeof(status));
  ASSERT_EQ(status, 0);

  ASSERT_TRUE(tablet.handle(make_frame(PLANK_RAW_HID_SUSPEND, 0, 7, nullptr, 0)));
  EXPECT_FALSE(tablet.handle(make_frame(PLANK_RAW_HID_SUSPEND, 1, 7, nullptr, 0)));
  EXPECT_FALSE(tablet.handle(make_frame(PLANK_RAW_HID_SUSPEND, 0, 8, nullptr, 0)));
  auto malformed_suspend = make_frame(PLANK_RAW_HID_SUSPEND, 0, 7, nullptr, 0);
  reinterpret_cast<PLANK_RAW_HID_WIRE_HEADER *>(malformed_suspend.data())->transactionId =
    util::endian::little<std::uint32_t>(1);
  EXPECT_FALSE(tablet.handle(malformed_suspend));
  const std::uint8_t invalid_suspend_payload = 0;
  EXPECT_FALSE(tablet.handle(make_frame(
    PLANK_RAW_HID_SUSPEND,
    0,
    7,
    &invalid_suspend_payload,
    sizeof(invalid_suspend_payload)
  )));
  ASSERT_TRUE(tablet.handle(make_frame(PLANK_RAW_HID_DEVICE, 0, 8, &device, sizeof(device))));
  ASSERT_TRUE(tablet.handle(make_frame(PLANK_RAW_HID_DESCRIPTOR, 0, 8, descriptor, sizeof(descriptor))));

  EXPECT_EQ(tablet.active_generation(), 8);
  EXPECT_EQ(tablet.endpoint_epoch(), initial_epoch);

  tablet.suspend();
  const auto resumed_mail = std::make_shared<safe::mail_raw_t>();
  tablet.rebind(resumed_mail->queue<std::vector<std::uint8_t>>("raw-hid-test-resumed"));
  ASSERT_TRUE(tablet.handle(make_frame(PLANK_RAW_HID_DEVICE, 0, 9, &device, sizeof(device))));
  ASSERT_TRUE(tablet.handle(make_frame(PLANK_RAW_HID_DESCRIPTOR, 0, 9, descriptor, sizeof(descriptor))));

  EXPECT_EQ(tablet.active_generation(), 9);
  EXPECT_EQ(tablet.endpoint_epoch(), initial_epoch);

  device.product = util::endian::little<std::uint32_t>(0x0357);
  ASSERT_TRUE(tablet.handle(make_frame(PLANK_RAW_HID_DEVICE, 0, 10, &device, sizeof(device))));
  ASSERT_TRUE(tablet.handle(make_frame(PLANK_RAW_HID_DESCRIPTOR, 0, 10, descriptor, sizeof(descriptor))));
  EXPECT_GT(tablet.endpoint_epoch(), initial_epoch);
}
