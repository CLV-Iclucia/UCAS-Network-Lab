#ifndef __UTIL_H__
#define __UTIL_H__

#include <sys/time.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __has_builtin
  #if __has_builtin(__builtin_popcount)
    #define USE_BUILTIN
    #define popcount(x) __builtin_popcount(x)
  #endif
#endif

#ifndef USE_BUILTIN
static inline int popcount(uint64_t x) {
    int count = 0;
    while (x) {
        count += x & 1;
        x >>= 1;
    }
    return count;
}
#endif

long get_interval(struct timeval tv_start,struct timeval tv_end);

#endif
