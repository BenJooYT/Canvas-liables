#pragma once

#include <cstdint>

namespace WsDiag {
    void SetLogTarget(int fd, const char *path);
    void Install(std::uintptr_t libBase);
}
