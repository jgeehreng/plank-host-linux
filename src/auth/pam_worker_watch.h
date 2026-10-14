/**
 * @file src/auth/pam_worker_watch.h
 * @brief Reap PAM children and bound cleanup after their caller disconnects.
 */
#pragma once

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <map>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace plank::auth {
  /**
   * @brief Parent-only ownership of worker PIDs and duplicate caller sockets.
   *
   * Watching RDHUP does not consume PAM traffic. A healthy session has no time
   * limit. Once its caller leaves, PAM gets a cleanup grace period, after which
   * a stuck worker is killed. Reap before kill so an exited PID cannot be reused.
   */
  class pam_workers_t {
  public:
    using clock_t = std::chrono::steady_clock;  ///< Monotonic cleanup clock.

    /** @brief Set the cleanup grace. @param grace Time allowed for PAM cleanup. */
    explicit pam_workers_t(std::chrono::milliseconds grace = std::chrono::seconds {2}):
        grace_ {grace} {}

    /** @brief Cancel and reap remaining children without an unbounded waitpid. */
    ~pam_workers_t() {
      stop();
    }

    pam_workers_t(const pam_workers_t &) = delete;
    pam_workers_t &operator=(const pam_workers_t &) = delete;

    /** @brief Track a forked worker. @param pid Child PID. @param fd Owned caller socket. */
    void add(pid_t pid, int fd) {
      workers_.emplace(pid, worker_t {fd});
    }

    /** @brief Active workers, including those still cleaning up. @return Count. */
    std::size_t size() const {
      return workers_.size();
    }

    /** @brief Close other workers' inherited sockets in a newly forked child. */
    void close_in_child() const {
      for (const auto &[pid, worker] : workers_) {
        ::close(worker.fd);
      }
    }

    /** @brief Reap exits and terminate abandoned workers. @return Number killed this iteration. */
    std::size_t maintain() {
      std::size_t killed = 0;
      const auto now = clock_t::now();
      for (auto it = workers_.begin(); it != workers_.end();) {
        const pid_t pid = it->first;
        auto &worker = it->second;
        const auto reaped = waitpid(pid, nullptr, WNOHANG);
        if (reaped == pid || (reaped < 0 && errno == ECHILD)) {
          ::close(worker.fd);
          it = workers_.erase(it);
          continue;
        }
        pollfd state {worker.fd, POLLRDHUP, 0};
        if (worker.deadline == clock_t::time_point::max() && poll(&state, 1, 0) > 0 && (state.revents & (POLLRDHUP | POLLHUP | POLLERR))) {
          worker.deadline = now + grace_;
        }
        if (now >= worker.deadline && !worker.killed) {
          kill(pid, SIGKILL);
          worker.killed = true;
          ++killed;
        }
        ++it;
      }
      return killed;
    }

    /** @brief Close caller channels, allow cleanup, then kill stragglers on shutdown. */
    void stop() {
      if (workers_.empty()) {
        return;
      }
      const auto deadline = clock_t::now() + grace_;
      for (auto &[pid, worker] : workers_) {
        shutdown(worker.fd, SHUT_RDWR);
        worker.deadline = std::min(worker.deadline, deadline);
      }
      // Also bound reaping: SIGKILL cannot interrupt a kernel D-state task.
      const auto reap_deadline = deadline + std::chrono::seconds {1};
      while (!workers_.empty() && clock_t::now() < reap_deadline) {
        maintain();
        if (!workers_.empty()) {
          poll(nullptr, 0, 10);
        }
      }
      for (const auto &[pid, worker] : workers_) {
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, WNOHANG);
        ::close(worker.fd);
      }
      workers_.clear();
    }

  private:
    /** @brief One parent's watch descriptor and cleanup state. */
    struct worker_t {
      int fd;  ///< Socket also owned by this child.
      clock_t::time_point deadline = clock_t::time_point::max();  ///< Infinite while connected.
      bool killed = false;  ///< Send SIGKILL once, then wait for reaping.
    };

    std::chrono::milliseconds grace_;  ///< Time allowed for normal PAM teardown.
    std::map<pid_t, worker_t> workers_;  ///< Child ownership; accessed only in the parent loop.
  };
}  // namespace plank::auth
