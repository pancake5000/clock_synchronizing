#ifndef MIM_ERR_H
#define MIM_ERR_H

#include <stdnoreturn.h>

// Print information about a system error and quits.
[[noreturn]] void syserr(const char* fmt, ...);

// Print information about an error and quits.
[[noreturn]] void fatal(const char* fmt, ...);

// Print an error message without quitting.
void err_msg(const char* fmt, ...);

#endif
