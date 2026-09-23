//
// Created by ignite on 9/23/26.
//

#include <jni.h>
#include <string>
#include "system_properties.h"

extern "C"
JNIEXPORT jstring JNICALL
Java_com_guozilu_droidprobe_utils_SystemPropertiesUtils_getprop(JNIEnv *env, jclass clazz, jstring key) {
    if (key == nullptr) {
        return nullptr;
    }

    const char* key_chars = env->GetStringUTFChars(key, nullptr);
    if (key_chars == nullptr) {
        return nullptr;
    }

    std::string value = get_system_property(key_chars);
    env->ReleaseStringUTFChars(key, key_chars);
    if (value.empty()) {
        return nullptr;
    }

    return env->NewStringUTF(value.c_str());
}
