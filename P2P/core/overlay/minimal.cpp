// minimal C++ runtime for static linking with musl
#include <stdlib.h>
#include <stddef.h>

void* operator new(size_t size)
{
    return malloc(size);
}

void* operator new[](size_t size)
{
    return malloc(size);
}

void operator delete(void* ptr) noexcept
{
    free(ptr);
}

void operator delete[](void* ptr) noexcept
{
    free(ptr);
}

void operator delete(void* ptr, size_t) noexcept
{
    free(ptr);
}

void operator delete[](void* ptr, size_t) noexcept
{
    free(ptr);
}

extern "C" void __cxa_pure_virtual()
{
    abort();
}
