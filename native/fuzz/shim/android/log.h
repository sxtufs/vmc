#pragma once
/* Host-only no-op logging shim. */
#include <stdio.h>
#include <stdarg.h>

#define ANDROID_LOG_UNKNOWN 0
#define ANDROID_LOG_DEFAULT 1
#define ANDROID_LOG_VERBOSE 2
#define ANDROID_LOG_DEBUG 3
#define ANDROID_LOG_INFO 4
#define ANDROID_LOG_WARN 5
#define ANDROID_LOG_ERROR 6
#define ANDROID_LOG_FATAL 7
#define ANDROID_LOG_SILENT 8

__attribute__((format(printf, 3, 4)))
static inline int __android_log_print(int prio, const char *tag,
                                      const char *fmt, ...) {
    if (prio < ANDROID_LOG_ERROR) { (void)tag; (void)fmt; return 0; }
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", tag);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    return 0;
}
