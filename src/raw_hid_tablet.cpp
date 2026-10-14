/**
 * @file src/raw_hid_tablet.cpp
 * @brief Session-scoped raw HID tablet redirection implementation.
 */

#include "raw_hid_tablet.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>

#ifdef __linux__
  #include <dirent.h>
  #include <fcntl.h>
  #include <linux/uhid.h>
  #include <poll.h>
  #include <unistd.h>
#endif

extern "C" {
#include <moonlight-common-c/src/plank.h>
}

#include "logging.h"
#include "utility.h"

using namespace std::literals;

namespace raw_hid {
  namespace {
    constexpr std::int32_t success = 0;

    /**
     * @brief Read an unaligned little-endian protocol value.
     *
     * @tparam T Integral value type.
     * @param source Bytes containing the value.
     * @return Host-endian value.
     */
    template<typename T>
    T read_little(const T &source) {
      T value;
      std::memcpy(&value, &source, sizeof(value));
      return util::endian::little(value);
    }

    /**
     * @brief Write a little-endian protocol value without alignment assumptions.
     *
     * @tparam T Integral value type.
     * @param destination Field receiving the value.
     * @param value Host-endian value.
     */
    template<typename T>
    void write_little(T &destination, T value) {
      value = util::endian::little(value);
      std::memcpy(&destination, &value, sizeof(value));
    }

#ifdef __linux__
    /**
     * @brief Read the physical path of one input event node from sysfs.
     *
     * @param event_name Node name such as `event12`.
     * @return Physical path, or an empty string when unavailable.
     */
    std::string read_phys(const char *event_name) {
      std::ifstream file {"/sys/class/input/"s + event_name + "/device/phys"};
      std::string phys;
      std::getline(file, phys);
      return phys;
    }
#endif
  }  // namespace

  class tablet_t::impl_t {
  public:
    /**
     * @brief Initialize raw tablet session state.
     *
     * @param feedback_queue Queue carrying host control requests to the client.
     */
    explicit impl_t(feedback_queue_t feedback_queue):
        feedback_queue_ {std::move(feedback_queue)} {
    }

    /**
     * @brief Destroy all interfaces when the implementation is released.
     */
    ~impl_t() {
      reset();
    }

    /**
     * @brief Process a validated transport frame.
     *
     * @param frame Header and payload bytes.
     * @return True when the frame was accepted.
     */
    bool handle(const std::vector<std::uint8_t> &frame) {
      if (frame.size() < sizeof(PLANK_RAW_HID_WIRE_HEADER)) {
        return false;
      }

      PLANK_RAW_HID_WIRE_HEADER header;
      std::memcpy(&header, frame.data(), sizeof(header));
      const auto payload_length = read_little(header.payloadLength);
      if (read_little(header.magic) != PLANK_RAW_HID_WIRE_MAGIC ||
          read_little(header.version) != PLANK_RAW_HID_WIRE_VERSION ||
          payload_length > PLANK_RAW_HID_MAX_PAYLOAD_SIZE ||
          frame.size() != sizeof(header) + payload_length) {
        return false;
      }

      const auto type = static_cast<PLANK_RAW_HID_MESSAGE_TYPE>(read_little(header.type));
      const auto interface_id = read_little(header.interfaceId);
      const auto generation = read_little(header.generation);
      const auto transaction_id = read_little(header.transactionId);
      const std::span<const std::uint8_t> payload {frame.data() + sizeof(header), payload_length};

      if (type == PLANK_RAW_HID_DEVICE) {
        return begin_attach(generation, payload);
      }

      std::unique_lock lock {mutex_};
      if (!device_ || generation != generation_) {
        return false;
      }
      if (type == PLANK_RAW_HID_DESCRIPTOR) {
        const bool accepted = accept_descriptor(interface_id, payload);
        const bool replace_interfaces = replace_interfaces_;
        replace_interfaces_ = false;
        lock.unlock();
        return accepted && (!replace_interfaces || replace_group());
      }
      if (type == PLANK_RAW_HID_DETACH) {
        lock.unlock();
        reset();
        return true;
      }
      if (type == PLANK_RAW_HID_SUSPEND) {
        if (interface_id != 0 || transaction_id != 0 || !payload.empty() || uhid_fds_.empty()) {
          return false;
        }
        transport_active_ = false;
#ifdef __linux__
        cancel_report_requests();
        contacts_clean_ = release_retained_contacts();
#endif
        BOOST_LOG(info) << "Suspended raw HID tablet transport while retaining endpoints for generation "sv << generation_;
        return true;
      }
      if (!transport_active_) {
        return false;
      }
      if (interface_id >= uhid_fds_.size()) {
        return false;
      }

#ifdef __linux__
      if (type == PLANK_RAW_HID_INPUT && !payload.empty() && payload.size() <= UHID_DATA_MAX) {
        uhid_event event {};
        event.type = UHID_INPUT2;
        event.u.input2.size = static_cast<std::uint16_t>(payload.size());
        std::ranges::copy(payload, event.u.input2.data);
        return write_event(uhid_fds_[interface_id], event);
      }
      if (type == PLANK_RAW_HID_GET_REPORT_REPLY && payload.size() >= sizeof(std::int32_t)) {
        std::int32_t error;
        std::memcpy(&error, payload.data(), sizeof(error));
        error = util::endian::little(error);
        if (payload.size() - sizeof(error) > UHID_DATA_MAX) {
          return false;
        }
        uhid_event event {};
        event.type = UHID_GET_REPORT_REPLY;
        event.u.get_report_reply.id = transaction_id;
        event.u.get_report_reply.err = static_cast<std::uint16_t>(std::max(error, 0));
        event.u.get_report_reply.size = static_cast<std::uint16_t>(payload.size() - sizeof(error));
        std::copy(payload.begin() + sizeof(error), payload.end(), event.u.get_report_reply.data);
        const bool written = write_event(uhid_fds_[interface_id], event);
        if (written) {
          pending_reports_.erase({interface_id, transaction_id});
        }
        return written;
      }
      if (type == PLANK_RAW_HID_SET_REPORT_REPLY && payload.size() == sizeof(std::int32_t)) {
        std::int32_t error;
        std::memcpy(&error, payload.data(), sizeof(error));
        error = util::endian::little(error);
        uhid_event event {};
        event.type = UHID_SET_REPORT_REPLY;
        event.u.set_report_reply.id = transaction_id;
        event.u.set_report_reply.err = static_cast<std::uint16_t>(std::max(error, 0));
        const bool written = write_event(uhid_fds_[interface_id], event);
        if (written) {
          pending_reports_.erase({interface_id, transaction_id});
        }
        return written;
      }
#endif
      return false;
    }

    /**
     * @brief Replace the outbound control queue after session resume.
     *
     * @param feedback_queue New session queue.
     */
    void rebind(feedback_queue_t feedback_queue) {
      std::lock_guard lock {mutex_};
      feedback_queue_ = std::move(feedback_queue);
    }

    /**
     * @brief Stop accepting reports while preserving the kernel device nodes.
     */
    void suspend() {
      std::lock_guard lock {mutex_};
      transport_active_ = false;
      feedback_queue_ = {};
#ifdef __linux__
      cancel_report_requests();
      contacts_clean_ = release_retained_contacts();
#endif
    }

    /**
     * @brief Stop the poll worker and destroy all UHID interfaces.
     */
    void reset() {
#ifdef __linux__
      poll_thread_.request_stop();
      if (poll_thread_.joinable() && poll_thread_.get_id() != std::this_thread::get_id()) {
        poll_thread_.join();
      }
#endif
      std::lock_guard lock {mutex_};
#ifdef __linux__
      cancel_report_requests();
      destroy_interfaces();
#endif
      descriptors_.clear();
      started_.clear();
      device_.reset();
      retained_device_.reset();
      retained_descriptors_.clear();
      generation_ = 0;
      transport_active_ = false;
      replace_interfaces_ = false;
    }

    /**
     * @brief Return whether this session retains exact UHID endpoints.
     */
    bool has_endpoints() {
      std::lock_guard lock {mutex_};
      return !uhid_fds_.empty();
    }

#ifdef SUNSHINE_TESTS
    std::uint16_t active_generation() {
      std::lock_guard lock {mutex_};
      return generation_;
    }

    std::uint64_t endpoint_epoch() {
      std::lock_guard lock {mutex_};
      return endpoint_epoch_;
    }

    /** @brief Override contact cleanup only in the component-test build. */
    void set_contact_cleanup_for_test(std::function<bool()> cleanup) {
      std::lock_guard lock {mutex_};
      contact_cleanup_for_test_ = std::move(cleanup);
    }
#endif

  private:
    /**
     * @brief Start collecting metadata for a new device generation.
     *
     * @param generation Client-selected generation number.
     * @param payload Serialized device metadata.
     * @return True when metadata was accepted.
     */
    bool begin_attach(std::uint16_t generation, std::span<const std::uint8_t> payload) {
      if (payload.size() != sizeof(PLANK_RAW_HID_DEVICE_MESSAGE)) {
        return false;
      }
      PLANK_RAW_HID_DEVICE_MESSAGE device;
      std::memcpy(&device, payload.data(), sizeof(device));
      const auto interface_count = read_little(device.interfaceCount);
      if (generation == 0 || interface_count == 0 || interface_count > PLANK_RAW_HID_MAX_INTERFACES) {
        send_attach_result(generation, EINVAL);
        return false;
      }
      device.name[sizeof(device.name) - 1] = '\0';
      device.physical[sizeof(device.physical) - 1] = '\0';
      device.unique[sizeof(device.unique) - 1] = '\0';

      std::lock_guard lock {mutex_};
#ifdef __linux__
      cancel_report_requests();
      if (transport_active_) {
        contacts_clean_ = release_retained_contacts();
      }
#endif
      generation_ = generation;
      device_ = device;
      descriptors_.assign(interface_count, {});
      transport_active_ = false;
      return true;
    }

    /**
     * @brief Store one report descriptor and create the group when complete.
     *
     * @param interface_id Interface receiving the descriptor.
     * @param descriptor Original HID report descriptor.
     * @return True when the descriptor was accepted.
     */
    bool accept_descriptor(std::uint16_t interface_id, std::span<const std::uint8_t> descriptor) {
      if (interface_id >= descriptors_.size() || descriptor.empty() ||
          descriptor.size() > PLANK_RAW_HID_MAX_DESCRIPTOR_SIZE || !descriptors_[interface_id].empty()) {
        return false;
      }
      descriptors_[interface_id].assign(descriptor.begin(), descriptor.end());
      if (std::ranges::any_of(descriptors_, [](const auto &item) {
            return item.empty();
          })) {
        return true;
      }

      if (!uhid_fds_.empty() && retained_device_ &&
          std::memcmp(std::addressof(*retained_device_), std::addressof(*device_), sizeof(*device_)) == 0 &&
          retained_descriptors_ == descriptors_ &&
          std::ranges::all_of(started_, [](bool started) {
            return started;
          })) {
#ifdef __linux__
        // Retry a transient cleanup error before reusing the stable device.
        // Only a group whose cleanup still cannot be verified is replaced,
        // never a healthy group merely because the stream/focus changed.
        if (!contacts_clean_) {
          contacts_clean_ = release_retained_contacts();
          if (!contacts_clean_) {
            BOOST_LOG(warning) << "Replacing raw HID endpoints after contact cleanup failed twice"sv;
            replace_interfaces_ = true;
            return true;
          }
        }
#endif
        retained_device_ = device_;
        retained_descriptors_ = descriptors_;
        transport_active_ = true;
        BOOST_LOG(info) << "Reused stable raw HID tablet endpoints for generation "sv << generation_;
        send_attach_result(generation_, success);
        return true;
      }

      // An interrupted initial kernel probe is not a reusable tablet. Only
      // replace an incomplete group; fully started endpoints keep their IDs.
      replace_interfaces_ = true;
      return true;
    }

    /**
     * @brief Create one UHID endpoint per client HID interface.
     *
     * @return True when all create requests were written.
     */
    bool create_group() {
      contacts_clean_ = true;
#ifdef __linux__
      transport_active_ = true;
      started_.assign(descriptors_.size(), false);
      const auto &device = *device_;
      // Every interface shares one physical path so hid-wacom groups them.
      // Retained endpoints keep it for later generations, so it is stored
      // rather than rebuilt from generation_.
      const std::string physical = "plank/raw-tablet/" + std::to_string(generation_);
      for (const auto &descriptor : descriptors_) {
        const int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) {
          const int error_code = errno;
          transport_active_ = false;
          BOOST_LOG(error) << "Raw HID tablet cannot open /dev/uhid: "sv << std::strerror(error_code);
          destroy_interfaces();
          send_attach_result(generation_, error_code);
          return false;
        }
        uhid_fds_.push_back(fd);

        uhid_event create {};
        create.type = UHID_CREATE2;
        std::memcpy(create.u.create2.name, device.name, sizeof(device.name));
        std::memcpy(create.u.create2.phys, physical.data(), std::min(physical.size(), sizeof(create.u.create2.phys) - 1));
        std::memcpy(create.u.create2.uniq, device.unique, sizeof(device.unique));
        create.u.create2.rd_size = static_cast<std::uint16_t>(descriptor.size());
        create.u.create2.bus = read_little(device.bus);
        create.u.create2.vendor = read_little(device.vendor);
        create.u.create2.product = read_little(device.product);
        create.u.create2.version = read_little(device.version);
        create.u.create2.country = read_little(device.country);
        std::ranges::copy(descriptor, create.u.create2.rd_data);
        if (!write_event(fd, create)) {
          transport_active_ = false;
          destroy_interfaces();
          send_attach_result(generation_, EIO);
          return false;
        }
      }
      poll_thread_ = std::jthread {[this](std::stop_token stop_token) {
        poll_uhid(stop_token);
      }};
      retained_device_ = device_;
      retained_descriptors_ = descriptors_;
      retained_phys_ = physical;
#ifdef SUNSHINE_TESTS
      ++endpoint_epoch_;
#endif
      return true;
#else
      transport_active_ = false;
      send_attach_result(generation_, ENOTSUP);
      return false;
#endif
    }

#ifdef __linux__
    /**
     * @brief Complete in-flight kernel queries before retiring their transport lease.
     *
     * Caller holds mutex_. A client worker cancels stale completions on focus
     * loss, so the Host must answer requests already sent as well as new ones.
     * This leaves no synchronous hid-wacom query waiting on an old generation.
     */
    void cancel_report_requests() {
      for (const auto &[key, type] : pending_reports_) {
        const auto [interface_id, transaction_id] = key;
        uhid_event reply {};
        reply.type = type;
        if (type == UHID_GET_REPORT_REPLY) {
          reply.u.get_report_reply.id = transaction_id;
          reply.u.get_report_reply.err = ENOTCONN;
        } else {
          reply.u.set_report_reply.id = transaction_id;
          reply.u.set_report_reply.err = ENOTCONN;
        }
        if (interface_id < uhid_fds_.size() && !write_event(uhid_fds_[interface_id], reply)) {
          BOOST_LOG(warning) << "Unable to cancel suspended raw HID kernel request"sv;
        }
      }
      pending_reports_.clear();
    }

    /**
     * @brief Write a complete event to a UHID endpoint.
     *
     * @param fd UHID endpoint.
     * @param event Event to write.
     * @return True when the kernel accepted the event.
     */
    static bool write_event(int fd, const uhid_event &event) {
      ssize_t written;
      int retries = 4;
      do {
        written = write(fd, &event, sizeof(event));
      } while (written < 0 && errno == EINTR && --retries > 0);
      if (written != static_cast<ssize_t>(sizeof(event))) {
        BOOST_LOG(error) << "Raw HID tablet UHID write failed: "sv << std::strerror(errno);
        return false;
      }
      return true;
    }

    /**
     * @brief Destroy and close every partially or fully created UHID endpoint.
     */
    void destroy_interfaces() {
      uhid_event destroy {};
      destroy.type = UHID_DESTROY;
      for (const int fd : uhid_fds_) {
        write_event(fd, destroy);
        close(fd);
      }
      uhid_fds_.clear();
      retained_phys_.clear();
    }

    /**
     * @brief End contact held on the input nodes of the retained endpoints.
     *
     * The endpoints and their XInput identities survive a suspend, so the
     * kernel would otherwise keep the last reported tip, buttons, keys and
     * touches until the next report, which then draws from the old contact
     * point to the new one. Only releases are injected; tool proximity stays.
     * evdev injects through its shared input handle, including when an evdev
     * reader owns a grab. Verify input-core state before reporting success.
     * @return True only when all discovered endpoints were verified idle.
     */
    bool release_retained_contacts() {
  #ifdef SUNSHINE_TESTS
      if (contact_cleanup_for_test_) {
        return contact_cleanup_for_test_();
      }
  #endif
      if (retained_phys_.empty()) {
        return true;
      }
      DIR *directory = opendir("/sys/class/input");
      if (directory == nullptr) {
        const int error_code = errno;
        BOOST_LOG(warning) << "Raw HID tablet cannot scan retained input nodes: "sv << std::strerror(error_code);
        return false;
      }
      int released = 0;
      int matched = 0;
      bool clean = true;
      for (;;) {
        errno = 0;
        const dirent *entry = readdir(directory);
        if (entry == nullptr) {
          const int error_code = errno;
          if (error_code != 0) {
            clean = false;
            BOOST_LOG(warning) << "Raw HID tablet input-node scan failed: "sv << std::strerror(error_code);
          }
          break;
        }
        if (std::strncmp(entry->d_name, "event", 5) != 0 || read_phys(entry->d_name) != retained_phys_) {
          continue;
        }
        ++matched;
        const std::string path = "/dev/input/"s + entry->d_name;
        const int fd = open(path.c_str(), O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) {
          clean = false;
          const int error_code = errno;
          BOOST_LOG(warning) << "Raw HID tablet cannot open "sv << path << " to release contact: "sv << std::strerror(error_code);
          continue;
        }
        const auto result = release_node_contacts(fd);
        if (result.error != 0) {
          clean = false;
          BOOST_LOG(warning) << "Raw HID tablet contact cleanup failed on "sv << path << " ("sv << result.operation << "): "sv << std::strerror(result.error);
        } else if (result.released) {
          ++released;
        }
        close(fd);
      }
      closedir(directory);
      if (released != 0) {
        BOOST_LOG(info) << "Released held raw HID tablet contact on "sv << released << " input node(s)"sv;
      }
      if (matched == 0) {
        BOOST_LOG(warning) << "Raw HID contact cleanup could not verify any retained input nodes"sv;
      }
      return clean && matched != 0;
    }

    /**
     * @brief Stop the UHID poller and remove endpoints without clearing a pending attach.
     */
    bool replace_group() {
      poll_thread_.request_stop();
      if (poll_thread_.joinable() && poll_thread_.get_id() != std::this_thread::get_id()) {
        poll_thread_.join();
      }
      std::lock_guard lock {mutex_};
      destroy_interfaces();
      retained_device_.reset();
      retained_descriptors_.clear();
      return create_group();
    }

    /**
     * @brief Relay kernel control requests to the remote physical device.
     *
     * @param stop_token Session shutdown signal.
     */
    void poll_uhid(std::stop_token stop_token) {
      std::vector<pollfd> poll_fds;
      {
        std::lock_guard lock {mutex_};
        poll_fds.reserve(uhid_fds_.size());
        for (const int fd : uhid_fds_) {
          poll_fds.push_back({fd, POLLIN, 0});
        }
      }

      while (!stop_token.stop_requested()) {
        const int result = poll(poll_fds.data(), poll_fds.size(), 100);
        if (result < 0 && errno != EINTR) {
          break;
        }
        for (std::size_t index = 0; index < poll_fds.size(); ++index) {
          if ((poll_fds[index].revents & POLLIN) == 0) {
            continue;
          }
          uhid_event event {};
          const auto bytes = read(poll_fds[index].fd, &event, sizeof(event));
          if (bytes < static_cast<ssize_t>(sizeof(event.type))) {
            continue;
          }
          handle_uhid_event(static_cast<std::uint16_t>(index), event);
        }
      }
    }

    /**
     * @brief Serialize one kernel UHID lifecycle or report request.
     *
     * @param interface_id Client HID interface index.
     * @param event Kernel event.
     */
    void handle_uhid_event(std::uint16_t interface_id, const uhid_event &event) {
      std::lock_guard lock {mutex_};
      if (interface_id >= uhid_fds_.size()) {
        return;
      }
      if (event.type == UHID_START) {
        started_[interface_id] = true;
        if (transport_active_ && std::ranges::all_of(started_, [](bool started) {
              return started;
            })) {
          send_attach_result(generation_, success);
        }
      } else if (!transport_active_) {
        // A kernel request is synchronous. Complete it while suspended rather
        // than leaving hid-wacom blocked until the kernel's request timeout.
        uhid_event reply {};
        if (event.type == UHID_GET_REPORT) {
          reply.type = UHID_GET_REPORT_REPLY;
          reply.u.get_report_reply.id = event.u.get_report.id;
          reply.u.get_report_reply.err = ENOTCONN;
        } else if (event.type == UHID_SET_REPORT) {
          reply.type = UHID_SET_REPORT_REPLY;
          reply.u.set_report_reply.id = event.u.set_report.id;
          reply.u.set_report_reply.err = ENOTCONN;
        } else {
          return;
        }
        write_event(uhid_fds_[interface_id], reply);
      } else if (event.type == UHID_OPEN) {
        send_frame(PLANK_RAW_HID_OPEN, interface_id, 0, {});
      } else if (event.type == UHID_CLOSE) {
        send_frame(PLANK_RAW_HID_CLOSE, interface_id, 0, {});
      } else if (event.type == UHID_GET_REPORT) {
        pending_reports_[{interface_id, event.u.get_report.id}] = UHID_GET_REPORT_REPLY;
        const std::array<std::uint8_t, 2> request {event.u.get_report.rnum, event.u.get_report.rtype};
        send_frame(PLANK_RAW_HID_GET_REPORT, interface_id, event.u.get_report.id, request);
      } else if (event.type == UHID_SET_REPORT) {
        pending_reports_[{interface_id, event.u.set_report.id}] = UHID_SET_REPORT_REPLY;
        std::vector<std::uint8_t> request {event.u.set_report.rtype};
        request.insert(request.end(), event.u.set_report.data, event.u.set_report.data + event.u.set_report.size);
        send_frame(PLANK_RAW_HID_SET_REPORT, interface_id, event.u.set_report.id, request);
      } else if (event.type == UHID_OUTPUT) {
        std::vector<std::uint8_t> output {event.u.output.rtype};
        output.insert(output.end(), event.u.output.data, event.u.output.data + event.u.output.size);
        send_frame(PLANK_RAW_HID_OUTPUT, interface_id, 0, output);
      }
    }
#endif

    /**
     * @brief Send the result of creating an entire interface group.
     *
     * @param generation Device generation being acknowledged.
     * @param error Zero for success or a positive errno value.
     */
    void send_attach_result(std::uint16_t generation, std::int32_t error) {
      const auto little_error = util::endian::little(error);
      const std::span<const std::uint8_t> payload {reinterpret_cast<const std::uint8_t *>(&little_error), sizeof(little_error)};
      send_frame(PLANK_RAW_HID_ATTACH_RESULT, 0, 0, payload, generation);
    }

    /**
     * @brief Queue one raw HID frame for encrypted host-to-client delivery.
     *
     * @param type Raw HID message type.
     * @param interface_id Client HID interface index.
     * @param transaction_id Correlation identifier.
     * @param payload Message payload.
     * @param generation Optional generation override for attach failures.
     */
    void send_frame(PLANK_RAW_HID_MESSAGE_TYPE type, std::uint16_t interface_id, std::uint32_t transaction_id,
                    std::span<const std::uint8_t> payload, std::uint16_t generation = 0) {
      std::lock_guard lock {mutex_};
      std::vector<std::uint8_t> frame(sizeof(PLANK_RAW_HID_WIRE_HEADER) + payload.size());
      PLANK_RAW_HID_WIRE_HEADER header {};
      write_little(header.magic, static_cast<std::uint32_t>(PLANK_RAW_HID_WIRE_MAGIC));
      write_little(header.version, static_cast<std::uint16_t>(PLANK_RAW_HID_WIRE_VERSION));
      write_little(header.type, static_cast<std::uint16_t>(type));
      write_little(header.interfaceId, interface_id);
      write_little(header.generation, generation == 0 ? generation_ : generation);
      write_little(header.transactionId, transaction_id);
      write_little(header.payloadLength, static_cast<std::uint32_t>(payload.size()));
      std::memcpy(frame.data(), &header, sizeof(header));
      std::ranges::copy(payload, frame.begin() + sizeof(header));

      if (feedback_queue_ && !feedback_queue_->raise_reliable(std::move(frame), 100ms)) {
        // Signal the control loop to fail the session instead of silently
        // losing a feature request or attach acknowledgement.
        feedback_queue_->stop();
      }
    }

    std::recursive_mutex mutex_;  ///< Protects device state and the outbound queue binding.
    feedback_queue_t feedback_queue_;  ///< Current session control queue.
    std::optional<PLANK_RAW_HID_DEVICE_MESSAGE> device_;  ///< Client USB identity for the pending group.
    std::uint16_t generation_ = 0;  ///< Active client generation.
    std::vector<std::vector<std::uint8_t>> descriptors_;  ///< Original report descriptors by interface.
    std::vector<bool> started_;  ///< Kernel start state by interface.
    std::vector<int> uhid_fds_;  ///< UHID endpoints by interface.
    std::optional<PLANK_RAW_HID_DEVICE_MESSAGE> retained_device_;  ///< Identity backing retained UHID endpoints.
    std::vector<std::vector<std::uint8_t>> retained_descriptors_;  ///< Descriptors backing retained endpoints.
    std::string retained_phys_;  ///< Physical path shared by the retained endpoints' input nodes.
    bool transport_active_ = false;  ///< Whether the current transport may deliver tablet frames.
    bool contacts_clean_ = true;  ///< Last suspend verified releases, or no previous contacts exist.
    bool replace_interfaces_ = false;  ///< Whether a completed attach requires endpoint replacement.
#ifdef SUNSHINE_TESTS
    std::uint64_t endpoint_epoch_ = 0;  ///< Number of successfully created endpoint groups.
    std::function<bool()> contact_cleanup_for_test_;  ///< Component-test syscall boundary.
#endif
#ifdef __linux__
    std::map<std::pair<std::uint16_t, std::uint32_t>, std::uint32_t> pending_reports_;  ///< Kernel queries awaiting the active Client lease.
    std::jthread poll_thread_;  ///< Worker relaying kernel control requests.
#endif
  };

  bool available() {
#ifdef __linux__
    const int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
      return false;
    }
    close(fd);
    return true;
#else
    return false;
#endif
  }

  tablet_t::tablet_t(feedback_queue_t feedback_queue):
      impl_ {std::make_unique<impl_t>(std::move(feedback_queue))} {
  }

  tablet_t::~tablet_t() = default;

  bool tablet_t::handle(const std::vector<std::uint8_t> &frame) {
    return impl_->handle(frame);
  }

  void tablet_t::rebind(feedback_queue_t feedback_queue) {
    impl_->rebind(std::move(feedback_queue));
  }

  void tablet_t::suspend() {
    impl_->suspend();
  }

  void tablet_t::reset() {
    impl_->reset();
  }

  bool tablet_t::has_endpoints() {
    return impl_->has_endpoints();
  }

#ifdef SUNSHINE_TESTS
  std::uint16_t tablet_t::active_generation() {
    return impl_->active_generation();
  }

  std::uint64_t tablet_t::endpoint_epoch() {
    return impl_->endpoint_epoch();
  }

  void tablet_t::set_contact_cleanup_for_test(std::function<bool()> cleanup) {
    impl_->set_contact_cleanup_for_test(std::move(cleanup));
  }
#endif
}  // namespace raw_hid
