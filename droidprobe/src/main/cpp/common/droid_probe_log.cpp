//
// Created by ignite on 9/28/26.
//

#include "droid_probe_log.h"

void DroidProbe::Log::verbose(const char *tag, const char *format, ...) {
    va_list args;
    va_start(args, format);
    __android_log_vprint(ANDROID_LOG_VERBOSE, tag, format, args);
    va_end(args);
}

void DroidProbe::Log::debug(const char *tag, const char *format, ...) {
    va_list args;
    va_start(args, format);
    __android_log_vprint(ANDROID_LOG_DEBUG, tag, format, args);
    va_end(args);
}

void DroidProbe::Log::info(const char *tag, const char *format, ...) {
    va_list args;
    va_start(args, format);
    __android_log_vprint(ANDROID_LOG_INFO, tag, format, args);
    va_end(args);
}

void DroidProbe::Log::warn(const char *tag, const char *format, ...) {
    va_list args;
    va_start(args, format);
    __android_log_vprint(ANDROID_LOG_WARN, tag, format, args);
    va_end(args);
}

void DroidProbe::Log::error(const char *tag, const char *format, ...) {
    va_list args;
    va_start(args, format);
    __android_log_vprint(ANDROID_LOG_ERROR, tag, format, args);
    va_end(args);
}
