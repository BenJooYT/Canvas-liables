#include "WsDiag.h"

#include <shadowhook.h>

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <signal.h>
#include <thread>
#include <ucontext.h>
#include <unistd.h>

#include "../../include/misc/Logger.h"

namespace {

// Sky 0.35.2 (libBootloader.so, arm64-v8a).
//   update wrapper: RVA 0x1a88d8c
//     0x1a88d8c: a9bb7bfd   stp x29, x30, [sp, #-0x50]!
//   websocket step: RVA 0x1a890f0
//     0x1a890f0: 6dbc23e9   stp d9, d8, [sp, #-0x40]!
constexpr std::uintptr_t kUpdateRva = 0x1a88d8c;
constexpr std::uintptr_t kStepRva = 0x1a890f0;
constexpr std::uintptr_t kRequestRva = 0xfaef7c;
constexpr std::uintptr_t kUrlRva = 0xf59820;
constexpr std::uint32_t kUpdatePrologue = 0xa9bb7bfd;
constexpr std::uint32_t kStepPrologue = 0x6dbc23e9;
constexpr std::uint32_t kRequestPrologue = 0xa9bc7bfd;
constexpr std::uint32_t kUrlPrologue = 0xa9bb7bfd;

// Gate offsets decoded from the wrapper (0x1a88d8c..0x1a88e2c).
constexpr std::uintptr_t kStateOffset = 0x98810;    // [self] state, states 0..4
constexpr std::uintptr_t kContextOffset = 0x28;     // [self] -> account client
constexpr std::uintptr_t kClientConfigOffset = 0x10;
constexpr std::uintptr_t kEndpointOffset = 0x20;
constexpr std::uintptr_t kGateStateOffset = 0x14b4; // must equal 0x1c
constexpr std::uintptr_t kGatePairOffset0 = 0x2d0;  // pair must be non-zero
constexpr std::uintptr_t kGatePairOffset1 = 0x2d8;

using UpdateFn = void (*)(void *, void *, void *, void *, void *, void *);
using StepFn = void (*)(void *, void *, void *, void *, void *);
using RequestFn = int (*)(void *, int, void *);
using UrlFn = void (*)(void *, const char *, void *, void *);

UpdateFn g_updateOrig = nullptr;
StepFn g_stepOrig = nullptr;
RequestFn g_requestOrig = nullptr;
UrlFn g_urlOrig = nullptr;
std::atomic<std::uint32_t> g_updateCalls{0};
std::atomic<std::uint32_t> g_stepCalls{0};
std::atomic<std::uint32_t> g_lastState{0xffffffffu};
std::atomic<std::uint32_t> g_lastStepState{0xffffffffu};
std::atomic<std::uint32_t> g_lastGate{0xffffffffu};
std::atomic<bool> g_installed{false};
std::uintptr_t g_libBase = 0;

std::mutex g_logMutex;
int g_logFd = -1;

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
}

void CrashHandler(int sig, siginfo_t *info, void *context) {
    auto *uc = static_cast<ucontext_t *>(context);
    const std::uintptr_t pc = uc != nullptr ? uc->uc_mcontext.pc : 0;
    const std::uintptr_t lr = uc != nullptr ? uc->uc_mcontext.regs[30] : 0;
    const std::uintptr_t sp = uc != nullptr ? uc->uc_mcontext.sp : 0;
    const std::uintptr_t fp = uc != nullptr ? uc->uc_mcontext.regs[29] : 0;

    char buf[384];
    const int n = std::snprintf(
            buf, sizeof(buf),
            "WS CRASH sig=%d addr=%p pc=%p lr=%p sp=%p fp=%p rva=0x%lx "
            "update=%u step=%u state=%u gate=%u\n",
            sig, info != nullptr ? info->si_addr : nullptr,
            reinterpret_cast<void *>(pc), reinterpret_cast<void *>(lr),
            reinterpret_cast<void *>(sp), reinterpret_cast<void *>(fp),
            static_cast<unsigned long>(pc - g_libBase),
            g_updateCalls.load(), g_stepCalls.load(),
            g_lastState.load(), g_lastGate.load());
    if (n > 0 && g_logFd >= 0) {
        ssize_t ignored = write(g_logFd, buf, static_cast<size_t>(n));
        (void) ignored;
    }

    signal(sig, SIG_DFL);
    raise(sig);
}

void InstallCrashHandler(std::uintptr_t libBase) {
    g_libBase = libBase;
    struct sigaction action{};
    action.sa_sigaction = CrashHandler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    const int signals[] = {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE};
    for (int sig : signals) {
        sigaction(sig, &action, nullptr);
    }
}

void StartHeartbeat() {
    std::thread([] {
        for (;;) {
            sleep(15);
            WriteLine("WS heartbeat update=%u step=%u state=%u gate=%u",
                      g_updateCalls.load(), g_stepCalls.load(),
                      g_lastState.load(), g_lastGate.load());
        }
    }).detach();
}

inline std::uint32_t Read32(const void *base, std::uintptr_t offset) {
    return *reinterpret_cast<const volatile std::uint32_t *>(
            static_cast<const char *>(base) + offset);
}

inline const void *ReadPtr(const void *base, std::uintptr_t offset) {
    return *reinterpret_cast<const void *const volatile *>(
            static_cast<const char *>(base) + offset);
}

void LogWords(const char *label, const void *base, std::uintptr_t offset) {
    if (base == nullptr) return;
    const auto *words = reinterpret_cast<const volatile std::uint32_t *>(
            static_cast<const char *>(base) + offset);
    WriteLine("%s=%08x %08x %08x %08x", label, words[0], words[1], words[2], words[3]);
}

void LogText(const char *label, const void *base, std::uintptr_t offset, std::size_t max) {
    if (base == nullptr) return;
    char text[257];
    if (max > sizeof(text) - 1) max = sizeof(text) - 1;
    std::memcpy(text, static_cast<const char *>(base) + offset, max);
    text[max] = 0;
    for (std::size_t i = 0; i < max && text[i] != 0; ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (c < 0x20 || c > 0x7e) text[i] = '.';
    }
    WriteLine("%s=%s", label, text);
}

void UpdateHook(void *self, void *a1, void *a2, void *a3, void *a4, void *a5) {
    const std::uint32_t n = ++g_updateCalls;
    const std::uint32_t state = self ? Read32(self, kStateOffset) : 0xffffffffu;
    const std::uint32_t gate = a1 ? Read32(a1, kGateStateOffset) : 0xffffffffu;
    const std::uint32_t previousGate = g_lastGate.exchange(gate);
    g_lastState.store(state);

    if (n <= 5 || gate != previousGate || (n % 300u) == 0) {
        const void *pair0 = a5 ? ReadPtr(a5, kGatePairOffset0) : nullptr;
        const void *pair1 = a5 ? ReadPtr(a5, kGatePairOffset1) : nullptr;
        WriteLine("WS update #%u self=%p state=%u gate14b4=%u pair=%p/%p",
                  n, self, state, gate, pair0, pair1);
    }
    if (g_updateOrig) {
        g_updateOrig(self, a1, a2, a3, a4, a5);
    }
}

void StepHook(void *self, void *a1, void *a2, void *a3, void *a4) {
    const std::uint32_t n = ++g_stepCalls;
    const std::uint32_t state = self ? Read32(self, kStateOffset) : 0xffffffffu;
    const std::uint32_t previousState = g_lastStepState.exchange(state);
    if (n <= 5 || state != previousState || (n % 300u) == 0) {
        const void *client = self ? ReadPtr(self, kContextOffset) : nullptr;
        const void *config = client ? ReadPtr(client, kClientConfigOffset) : nullptr;
        const void *endpoint = config ? ReadPtr(config, kEndpointOffset) : nullptr;
        const void *pair0 = a4 ? ReadPtr(a4, kGatePairOffset0) : nullptr;
        const void *pair1 = a4 ? ReadPtr(a4, kGatePairOffset1) : nullptr;
        WriteLine("WS step #%u self=%p state=%u client=%p config=%p endpoint=%p arg4=%p pair=%p/%p",
                  n, self, state, client, config, endpoint, a4, pair0, pair1);
        LogWords("WS uuid-2c0", a4, 0x2c0);
        LogWords("WS tok-2d0", a4, 0x2d0);
        LogText("WS txt-2468", a4, 0x2468, 48);
        LogText("WS txt-2e0", a4, 0x2e0, 48);
    }
    if (g_stepOrig) {
        g_stepOrig(self, a1, a2, a3, a4);
    }
}

void UrlHook(void *self, const char *host, void *a3, void *a4) {
    char patched[256];
    const char *effective = host;
    if (host != nullptr) {
        const char *marker = std::strstr(host, ".ws.");
        if (marker != nullptr) {
            const std::size_t length = strnlen(host, sizeof(patched) - 1);
            if (length < sizeof(patched)) {
                std::memcpy(patched, host, length + 1);
                char *at = std::strstr(patched, ".ws.");
                std::memmove(at, at + 3, std::strlen(at + 3) + 1);
                effective = patched;
            }
        }
    }
    if (effective != host) {
        WriteLine("WS url host=%s -> %s", host, effective);
    } else {
        WriteLine("WS url host=%s", host != nullptr ? host : "(null)");
    }
    LogText("WS user", a3, 0, 40);
    LogText("WS tokenstr", a4, 0, 64);
    if (g_urlOrig) {
        g_urlOrig(self, effective, a3, a4);
    }
}

int RequestHook(void *self, int type, void *payload) {
    if (self == nullptr) {
        WriteLine("WS diag: null request builder (type=%d), skipping", type);
        return 0;
    }
    if (g_requestOrig) {
        return g_requestOrig(self, type, payload);
    }
    return 0;
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
    int target = -1;
    if (fd >= 0) {
        target = fd;
    } else if (path != nullptr) {
        target = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        g_logFd = target;
    }
    if (target >= 0) {
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

    InstallCrashHandler(libBase);
    StartHeartbeat();

    HookOne("update", libBase + kUpdateRva, kUpdatePrologue,
            reinterpret_cast<void *>(&UpdateHook),
            reinterpret_cast<void **>(&g_updateOrig));
    HookOne("step", libBase + kStepRva, kStepPrologue,
            reinterpret_cast<void *>(&StepHook),
            reinterpret_cast<void **>(&g_stepOrig));
    HookOne("request", libBase + kRequestRva, kRequestPrologue,
            reinterpret_cast<void *>(&RequestHook),
            reinterpret_cast<void **>(&g_requestOrig));
    HookOne("url", libBase + kUrlRva, kUrlPrologue,
            reinterpret_cast<void *>(&UrlHook),
            reinterpret_cast<void **>(&g_urlOrig));
}

} // namespace WsDiag
