#include "WsDiag.h"

#include <shadowhook.h>

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>

#include "../../include/misc/Logger.h"

namespace {

// Sky 0.35.2 (libBootloader.so, arm64-v8a).
//   update wrapper: RVA 0x1a88d8c
//     0x1a88d8c: a9bb7bfd   stp x29, x30, [sp, #-0x50]!
//   websocket step: RVA 0x1a890f0
//     0x1a890f0: 6dbc23e9   stp d9, d8, [sp, #-0x40]!
constexpr std::uintptr_t kUpdateRva = 0x1a88d8c;
constexpr std::uintptr_t kStepRva = 0x1a890f0;
constexpr std::uint32_t kUpdatePrologue = 0xa9bb7bfd;
constexpr std::uint32_t kStepPrologue = 0x6dbc23e9;

// Gate offsets decoded from the wrapper (0x1a88d8c..0x1a88e2c).
constexpr std::uintptr_t kStateOffset = 0x98810;    // [self] state, states 0..4
constexpr std::uintptr_t kContextOffset = 0x28;     // [self] -> account client
constexpr std::uintptr_t kClientConfigOffset = 0x10;
constexpr std::uintptr_t kEndpointOffset = 0x20;
constexpr std::uintptr_t kGateStateOffset = 0x14b4; // must equal 0x1c
constexpr std::uintptr_t kGatePairOffset0 = 0x2d0;  // pair must be non-zero
constexpr std::uintptr_t kGatePairOffset1 = 0x2d8;

using UpdateFn = void (*)(void *, void *, void *, void *, void *, void *);
using StepFn = void (*)(void *, void *, void *, void *);

UpdateFn g_updateOrig = nullptr;
StepFn g_stepOrig = nullptr;
std::atomic<std::uint32_t> g_updateCalls{0};
std::atomic<std::uint32_t> g_stepCalls{0};
std::atomic<bool> g_installed{false};

std::mutex g_logMutex;
int g_logFd = -1;
std::FILE *g_logFile = nullptr;

void WriteLine(const char *format, ...) {
    char body[512];
    va_list args;
    va_start(args, format);
    std::vsnprintf(body, sizeof(body), format, args);
    va_end(args);

    struct timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm local{};
    localtime_r(&ts.tv_sec, &local);

    char line[640];
    std::snprintf(line, sizeof(line), "%02d:%02d:%02d.%03ld %s",
                  local.tm_hour, local.tm_min, local.tm_sec,
                  ts.tv_nsec / 1000000L, body);

    LOGI("%s", line);

    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_logFd >= 0) {
        dprintf(g_logFd, "%s\n", line);
    }
    if (g_logFile != nullptr) {
        std::fprintf(g_logFile, "%s\n", line);
        std::fflush(g_logFile);
    }
}

inline std::uint32_t Read32(const void *base, std::uintptr_t offset) {
    return *reinterpret_cast<const volatile std::uint32_t *>(
            static_cast<const char *>(base) + offset);
}

inline const void *ReadPtr(const void *base, std::uintptr_t offset) {
    return *reinterpret_cast<const void *const volatile *>(
            static_cast<const char *>(base) + offset);
}

void UpdateHook(void *self, void *a1, void *a2, void *a3, void *a4, void *a5) {
    const std::uint32_t n = ++g_updateCalls;
    if (n <= 5 || (n % 300u) == 0) {
        const std::uint32_t state = self ? Read32(self, kStateOffset) : 0xffffffffu;
        const std::uint32_t gate = a1 ? Read32(a1, kGateStateOffset) : 0xffffffffu;
        const void *pair0 = a5 ? ReadPtr(a5, kGatePairOffset0) : nullptr;
        const void *pair1 = a5 ? ReadPtr(a5, kGatePairOffset1) : nullptr;
        WriteLine("WS update #%u self=%p state=%u gate14b4=%u pair=%p/%p",
                  n, self, state, gate, pair0, pair1);
    }
    if (g_updateOrig) {
        g_updateOrig(self, a1, a2, a3, a4, a5);
    }
}

void StepHook(void *self, void *a1, void *a2, void *a3) {
    const std::uint32_t n = ++g_stepCalls;
    if (n <= 5 || (n % 300u) == 0) {
        const std::uint32_t state = self ? Read32(self, kStateOffset) : 0xffffffffu;
        const void *client = self ? ReadPtr(self, kContextOffset) : nullptr;
        const void *config = client ? ReadPtr(client, kClientConfigOffset) : nullptr;
        const void *endpoint = config ? ReadPtr(config, kEndpointOffset) : nullptr;
        WriteLine("WS step #%u self=%p state=%u client=%p config=%p endpoint=%p",
                  n, self, state, client, config, endpoint);
    }
    if (g_stepOrig) {
        g_stepOrig(self, a1, a2, a3);
    }
}

bool HookOne(const char *name, std::uintptr_t address, std::uint32_t expected,
             void *hook, void **original) {
    const std::uint32_t prologue = *reinterpret_cast<const std::uint32_t *>(address);
    if (prologue != expected) {
        WriteLine("WS diag: %s at %p starts with %08x, expected %08x - not hooking",
                  name, reinterpret_cast<void *>(address), prologue, expected);
        return false;
    }
    if (shadowhook_hook_func_addr(reinterpret_cast<void *>(address), hook, original) == nullptr) {
        const int error = shadowhook_get_errno();
        WriteLine("WS diag: %s hook failed: %d - %s", name, error, shadowhook_to_errmsg(error));
        return false;
    }
    WriteLine("WS diag: hooked %s at %p", name, reinterpret_cast<void *>(address));
    return true;
}

} // namespace

namespace WsDiag {

void SetLogTarget(int fd, const char *path) {
    bool enabled;
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        if (fd >= 0) {
            g_logFd = fd;
            enabled = true;
        } else if (path != nullptr) {
            g_logFile = std::fopen(path, "a");
            enabled = g_logFile != nullptr;
        } else {
            enabled = false;
        }
    }
    if (enabled) {
        WriteLine("WS diag: log started");
    } else {
        LOGW("WS diag: no log target, logcat only");
    }
}

void Install(std::uintptr_t libBase) {
    bool expected = false;
    if (!g_installed.compare_exchange_strong(expected, true)) {
        return;
    }
    if (libBase == 0) {
        WriteLine("WS diag: libBootloader base not set, not hooking");
        return;
    }

    HookOne("update", libBase + kUpdateRva, kUpdatePrologue,
            reinterpret_cast<void *>(&UpdateHook),
            reinterpret_cast<void **>(&g_updateOrig));
    HookOne("step", libBase + kStepRva, kStepPrologue,
            reinterpret_cast<void *>(&StepHook),
            reinterpret_cast<void **>(&g_stepOrig));
}

} // namespace WsDiag
