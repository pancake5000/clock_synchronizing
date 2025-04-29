#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "err.h"

[[noreturn]] void syserr(const char *fmt, ...)
{
    va_list fmt_args;
    int org_errno = errno;

    std::cerr << "\tERROR: ";

    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);

    std::cerr << " (" << org_errno << "; " << strerror(org_errno) << ")" << std::endl;
    exit(1);
}

[[noreturn]] void fatal(const char *fmt, ...)
{
    va_list fmt_args;

    std::cerr << "\tERROR: ";

    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);

    std::cerr << std::endl;
    exit(1);
}

void err_msg(const char *fmt, ...)
{
    va_list fmt_args;

    std::cerr << "\tERROR MSG: ";

    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);

    std::cerr << std::endl;
}
