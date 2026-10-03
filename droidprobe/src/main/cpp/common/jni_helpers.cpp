//
// Created by ignite on 10/3/26.
//

#include "jni_helpers.hpp"
#include "droid_probe_log.h"

jstring DroidProbe::NewJavaString(JNIEnv* env, const std::string& value) {
    return NewJavaString(env, value.c_str());
} /* NewJavaString */

jstring DroidProbe::NewJavaString(JNIEnv* env, const char* value) {
    if (env == nullptr) {
        return nullptr;
    }

    return env->NewStringUTF(value);
} /* NewJavaString */

jobjectArray DroidProbe::NewStringArray(JNIEnv* env, const std::vector<std::string>& values) {
    return NewJavaArray(env, "java/lang/String", values,
        static_cast<jstring(*)(JNIEnv*, const std::string&)>(NewJavaString));
} /* NewStringArray */
