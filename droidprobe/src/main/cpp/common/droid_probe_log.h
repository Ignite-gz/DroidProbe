//
// Created by ignite on 9/28/26.
//

#ifndef DROIDPROBE_DROID_PROBE_LOG_H
#define DROIDPROBE_DROID_PROBE_LOG_H

#include <android/log.h>
#include <utility>
#include <string>

// android log tag, tag 为 "filename --- function_name"
#define DROID_PROBE_LOG_TAG ((std::string(__FILE_NAME__) + " --- " + __FUNCTION__).c_str())

// android log macro, tag 为 "filename --- function_name"
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE,  DROID_PROBE_LOG_TAG, ##__VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,  DROID_PROBE_LOG_TAG, ##__VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  DROID_PROBE_LOG_TAG, ##__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  DROID_PROBE_LOG_TAG, ##__VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,  DROID_PROBE_LOG_TAG, ##__VA_ARGS__)

namespace DroidProbe {
    class Log final {
    public:
        static void verbose(const char* tag, const char* format, ...);

        static void debug(const char* tag, const char* format, ...);

        static void info(const char* tag, const char* format, ...);

        static void warn(const char* tag, const char* format, ...);

        static void error(const char* tag, const char* format, ...);
    };
} // namespace DroidProbe

#endif // DROIDPROBE_DROID_PROBE_LOG_H
