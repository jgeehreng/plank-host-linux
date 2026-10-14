/**
 * @file src/process.cpp
 * @brief PLANK Desktop stream reservation state.
 */

// local includes
#include "display_device.h"
#include "logging.h"
#include "process.h"

namespace proc {
  using namespace std::literals;

  proc_t proc;

  namespace {
    /**
     * @brief Release the reservation while logging is still available.
     */
    class deinit_t: public platf::deinit_t {
    public:
      ~deinit_t() override {
        proc.terminate();
      }
    };
  }  // namespace

  bool is_desktop_app(const int app_id) noexcept {
    return app_id == desktop_app_id;
  }

  int proc_t::execute(const int app_id) {
    // Replace only the stream reservation, not desktop-owned input devices.
    terminate();

    if (!is_desktop_app(app_id)) {
      BOOST_LOG(error) << "Rejected non-Desktop application ID ["sv << app_id << ']';
      return 404;
    }

    _app_id.store(app_id, std::memory_order_release);
    BOOST_LOG(info) << "Reserving PLANK Desktop stream"sv;
    return 0;
  }

  int proc_t::running() const noexcept {
    return _app_id.load(std::memory_order_acquire);
  }

  void proc_t::terminate() {
    const int previous_app_id = _app_id.exchange(0, std::memory_order_acq_rel);
    if (previous_app_id != 0) {
      display_device::revert_configuration();
    }
  }

  std::unique_ptr<platf::deinit_t> init() {
    return std::make_unique<deinit_t>();
  }
}  // namespace proc
