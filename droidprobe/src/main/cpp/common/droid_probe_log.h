//
// Created by ignite on 9/28/26.
//

#ifndef DROIDPROBE_DROID_PROBE_LOG_H
#define DROIDPROBE_DROID_PROBE_LOG_H

#include <android/log.h>
#include <utility>

namespace DroidProbe {
    class Log final {
    public:
        static void verbose(const char *tag, const char *format, ...);
        static void debug(const char *tag, const char *format, ...);
        static void info(const char *tag, const char *format, ...);
        static void warn(const char *tag, const char *format, ...);
        static void error(const char *tag, const char *format, ...);
    };
} // namespace DroidProbe

#endif // DROIDPROBE_DROID_PROBE_LOG_H
