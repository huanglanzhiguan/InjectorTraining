#pragma once

#include <windows.h>

namespace lab
{
class UniqueHandle
{
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE handle) : value_(handle) {}

    ~UniqueHandle()
    {
        reset();
    }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : value_(other.release()) {}

    UniqueHandle& operator=(UniqueHandle&& other) noexcept
    {
        if (this != &other)
        {
            reset(other.release());
        }
        return *this;
    }

    HANDLE get() const
    {
        return value_;
    }

    bool valid() const
    {
        return value_ && value_ != INVALID_HANDLE_VALUE;
    }

    HANDLE release()
    {
        HANDLE handle = value_;
        value_ = nullptr;
        return handle;
    }

    void reset(HANDLE handle = nullptr)
    {
        if (valid())
        {
            CloseHandle(value_);
        }
        value_ = handle;
    }

private:
    HANDLE value_ = nullptr;
};
}

