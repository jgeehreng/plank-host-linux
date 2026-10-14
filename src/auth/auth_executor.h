/**
 * @file src/auth/auth_executor.h
 * @brief Bounded PAM executor, separate from the HTTPS event loop.
 */
#pragma once

#include <algorithm>
#include <array>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <poll.h>
#include <queue>
#include <stop_token>
#include <thread>
#include <unistd.h>
#include <vector>

namespace plank::auth {
  /** @brief Four concurrent authentication operations, with no additional backlog. */
  class auth_executor_t {
  public:
    using job_t = std::function<void(std::stop_token)>;  ///< Cancellation-aware request handler.

    /** @brief Start the fixed workers. */
    auth_executor_t() {
      active_.reserve(workers_.size());
      try {
        for (auto &worker : workers_) {
          worker = std::jthread {[this]() {
            run();
          }};
        }
        monitor_ = std::jthread {[this]() {
          monitor_peers();
        }};
      } catch (...) {
        stop();
        throw;
      }
    }

    /** @brief Cancel and join operations before their server/manager are destroyed. */
    ~auth_executor_t() {
      stop();
    }

    auth_executor_t(const auth_executor_t &) = delete;
    auth_executor_t &operator=(const auth_executor_t &) = delete;

    /**
     * @brief Admit bounded work and watch its peer without reading TLS bytes.
     * @param job Handler.
     * @param peer_fd Owned duplicate socket, or -1 for a non-network job. Consumed even on rejection.
     * @return False when busy/stopping.
     */
    bool submit(job_t job, int peer_fd = -1) {
      std::shared_ptr<work_t> work;
      try {
        work = std::make_shared<work_t>(std::move(job), peer_fd);
      } catch (...) {
        if (peer_fd >= 0) {
          close(peer_fd);
        }
        throw;
      }
      std::lock_guard lock {mutex_};
      if (stopping_ || active_.size() >= workers_.size()) {
        return false;
      }
      jobs_.push(work);
      active_.push_back(work);
      ready_.notify_one();
      peers_changed_.notify_one();
      return true;
    }

    /** @brief Cancel admitted work and join workers; callers must provide bounded operations. */
    void stop() {
      std::vector<std::shared_ptr<work_t>> active;
      {
        std::lock_guard lock {mutex_};
        stopping_ = true;
        active = active_;
        ready_.notify_all();
        peers_changed_.notify_all();
      }
      // Stop callbacks may call the manager; never invoke them under this lock.
      for (const auto &work : active) {
        work->cancellation.request_stop();
      }
      if (monitor_.joinable()) {
        monitor_.join();
      }
      for (auto &worker : workers_) {
        if (worker.joinable()) {
          worker.join();
        }
      }
    }

  private:
    /** @brief Stable FD/cancellation ownership; no descriptor-reuse race when the HTTP server closes. */
    struct work_t {
      job_t job;  ///< Only the executing worker accesses the callable.
      const int peer_fd;  ///< Duplicate of the peer socket, immutable until destruction.
      std::stop_source cancellation;  ///< Cancel only this operation when its peer leaves.

      /** @brief Own a job and optional peer socket. @param fn Handler. @param fd Owned descriptor. */
      work_t(job_t fn, int fd):
          job {std::move(fn)},
          peer_fd {fd} {}

      /** @brief Close the watch socket after all snapshots release it. */
      ~work_t() {
        if (peer_fd >= 0) {
          close(peer_fd);
        }
      }
    };

    /** @brief Monitor at most four sockets; sleep completely when authentication is idle. */
    void monitor_peers() {
      while (true) {
        std::vector<std::shared_ptr<work_t>> watched;
        {
          std::unique_lock lock {mutex_};
          peers_changed_.wait(lock, [this]() {
            return stopping_ || !active_.empty();
          });
          if (stopping_) {
            return;
          }
          watched = active_;
        }
        std::vector<pollfd> descriptors;
        for (const auto &work : watched) {
          // A disconnected socket stays readable forever. Once canceled,
          // exclude it from poll while its bounded operation drains.
          descriptors.push_back({work->cancellation.stop_requested() ? -1 : work->peer_fd, POLLRDHUP, 0});
        }
        if (poll(descriptors.data(), descriptors.size(), 100) > 0) {
          for (std::size_t i = 0; i < watched.size(); ++i) {
            if (descriptors[i].revents & (POLLRDHUP | POLLHUP | POLLERR | POLLNVAL)) {
              watched[i]->cancellation.request_stop();
            }
          }
        }
      }
    }

    /** @brief Drain admitted work; jobs must handle their own response/error reporting. */
    void run() {
      while (true) {
        std::shared_ptr<work_t> work;
        {
          std::unique_lock lock {mutex_};
          ready_.wait(lock, [this]() {
            return !jobs_.empty() || stopping_;
          });
          if (jobs_.empty()) {
            return;
          }
          work = std::move(jobs_.front());
          jobs_.pop();
        }
        try {
          work->job(work->cancellation.get_token());
        } catch (...) { /* Keep capacity available after a failed handler. */
        }
        // Destroy captured HTTP responses before advertising free capacity.
        work->job = {};
        std::lock_guard lock {mutex_};
        std::erase(active_, work);
      }
    }

    std::mutex mutex_;  ///< Protects admission and pending work.
    std::condition_variable ready_;  ///< Job/stop notification.
    std::condition_variable peers_changed_;  ///< Wake the idle peer monitor on admission/stop.
    std::queue<std::shared_ptr<work_t>> jobs_;  ///< Admitted work, included in active_.
    std::vector<std::shared_ptr<work_t>> active_;  ///< Running plus pending requests, at most four.
    bool stopping_ = false;  ///< Guarded by mutex_.
    std::array<std::jthread, 4> workers_;  ///< Bounded dedicated PAM workers.
    std::jthread monitor_;  ///< Peer-disconnect cancellation; never consumes credentials or TLS records.
  };
}  // namespace plank::auth
