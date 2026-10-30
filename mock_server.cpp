/*
 * mock_server.cpp — Multi-Threaded C++ TCP Server with Worker Thread Pool Handoff
 * Built with: clang++ -std=c++17 -g -O0 -fno-inline -fno-omit-frame-pointer -pthread mock_server.cpp -ldl -o mock_server
 * Demonstrates:
 *   1. I/O Thread (TID A): Socket recv -> parse_http_request -> validate_auth_header (dlopen libcrypto_mock.so)
 *   2. Condition Variable Handoff (TID A -> TID B): std::condition_variable::notify_one()
 *   3. Worker Thread (TID B): execute_storage_query (18ms baseline bottleneck vs 1.2ms --fast-storage) -> format_http_response -> send
 */

#include <arpa/inet.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

using VerifyTokenFn = int (*)(const char *);

struct RequestTask {
    int client_fd;
    std::string raw_request;
    bool fast_storage;
};

static std::mutex g_queue_mtx;
static std::condition_variable g_queue_cv;
static std::queue<RequestTask> g_task_queue;
static bool g_shutdown = false;
static VerifyTokenFn g_verify_fn = nullptr;

__attribute__((noinline)) std::string parse_http_request(const char *buf, size_t len) {
    if (!buf || len == 0) {
        return "";
    }
    std::string req(buf, len);
    volatile uint64_t checksum = 0;
    for (char c : req) {
        checksum = (checksum * 31) + static_cast<unsigned char>(c);
    }
    (void)checksum;
    return req;
}

__attribute__((noinline)) bool validate_auth_header(const std::string &req) {
    const char *token = "Bearer tok_1234567890_ebpf_tracer";
    if (req.find("Authorization:") != std::string::npos) {
        token = req.c_str();
    }
    if (g_verify_fn) {
        return g_verify_fn(token) != 0;
    }
    return true;
}

__attribute__((noinline)) std::string execute_storage_query(const std::string &query_key, bool fast_storage) {
    /*
     * PRIMARY BOTTLENECK SUSPECT (Baseline ~18.0ms vs Fast Mode ~1.2ms)
     * Combines simulated storage Block I/O wait + CPU scan so DWARF addr2line
     * pinpoints this exact function and source line in mock_server.cpp.
     */
    if (fast_storage) {
        std::this_thread::sleep_for(std::chrono::microseconds(1200));
    } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(18));
    }
    volatile uint64_t rows_scanned = 0;
    for (int i = 0; i < 4096; ++i) {
        rows_scanned += (static_cast<uint64_t>(i) ^ query_key.size());
    }
    return "{\"status\":\"ok\",\"rows\":" + std::to_string(rows_scanned & 0xff) + "}";
}

__attribute__((noinline)) std::string format_http_response(const std::string &payload) {
    std::string header =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "Content-Length: " +
        std::to_string(payload.size()) + "\r\n\r\n";
    return header + payload;
}

static void worker_thread_loop() {
    while (true) {
        RequestTask task{-1, "", false};
        {
            std::unique_lock<std::mutex> lk(g_queue_mtx);
            g_queue_cv.wait(lk, [] { return !g_task_queue.empty() || g_shutdown; });
            if (g_shutdown && g_task_queue.empty()) {
                return;
            }
            task = g_task_queue.front();
            g_task_queue.pop();
        }

        std::string db_result = execute_storage_query(task.raw_request, task.fast_storage);
        std::string http_resp = format_http_response(db_result);
        if (task.client_fd >= 0) {
            (void)::send(task.client_fd, http_resp.data(), http_resp.size(), 0);
            ::close(task.client_fd);
        }
    }
}

int main(int argc, char **argv) {
    int port = 8080;
    bool fast_storage = false;
    bool run_once = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            port = std::atoi(argv[++i]);
        } else if (arg == "--fast-storage" || arg == "--fast-mode") {
            fast_storage = true;
        } else if (arg == "--once") {
            run_once = true;
        }
    }

    void *lib_handle = ::dlopen("./libcrypto_mock.so", RTLD_NOW);
    if (!lib_handle && argc > 0 && argv[0]) {
        std::string bin_path(argv[0]);
        auto slash_pos = bin_path.find_last_of('/');
        if (slash_pos != std::string::npos) {
            std::string sibling_so = bin_path.substr(0, slash_pos + 1) + "libcrypto_mock.so";
            lib_handle = ::dlopen(sibling_so.c_str(), RTLD_NOW);
        }
    }
    if (lib_handle) {
        g_verify_fn = reinterpret_cast<VerifyTokenFn>(::dlsym(lib_handle, "verify_request_token"));
    }

    int srv_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) {
        std::perror("socket");
        return 1;
    }

    int opt = 1;
    ::setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (::bind(srv_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        std::perror("bind");
        ::close(srv_fd);
        return 1;
    }
    if (::listen(srv_fd, 16) < 0) {
        std::perror("listen");
        ::close(srv_fd);
        return 1;
    }

    std::thread worker(worker_thread_loop);

    while (true) {
        sockaddr_in cli_addr{};
        socklen_t cli_len = sizeof(cli_addr);
        int cli_fd = ::accept(srv_fd, reinterpret_cast<sockaddr *>(&cli_addr), &cli_len);
        if (cli_fd < 0) {
            break;
        }

        char buf[4096];
        ssize_t n = ::recv(cli_fd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            std::string parsed = parse_http_request(buf, static_cast<size_t>(n));
            bool auth_ok = validate_auth_header(parsed);
            if (auth_ok) {
                {
                    std::lock_guard<std::mutex> lk(g_queue_mtx);
                    g_task_queue.push(RequestTask{cli_fd, parsed, fast_storage});
                }
                g_queue_cv.notify_one();
            } else {
                ::close(cli_fd);
            }
        } else {
            ::close(cli_fd);
        }

        if (run_once) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            {
                std::lock_guard<std::mutex> lk(g_queue_mtx);
                g_shutdown = true;
            }
            g_queue_cv.notify_all();
            break;
        }
    }

    if (worker.joinable()) {
        worker.join();
    }
    ::close(srv_fd);
    if (lib_handle) {
        ::dlclose(lib_handle);
    }
    return 0;
}
