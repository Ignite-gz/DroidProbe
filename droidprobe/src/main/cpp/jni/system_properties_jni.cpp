//
// Created by ignite on 9/23/26.
//

#include <jni.h>
#include <string>
#include "system_properties.h"
#include "mount_info.h"

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

    std::string value = DroidProbe::get_system_property(key_chars);
    env->ReleaseStringUTFChars(key, key_chars);
    if (value.empty()) {
        return nullptr;
    }

    return env->NewStringUTF(value.c_str());
}

extern "C"
JNIEXPORT jobjectArray JNICALL
Java_com_guozilu_droidprobe_utils_MountUtils_getMountsNative(JNIEnv *env, jclass clazz) {
    // TODO: implement getMountsNative()
    std::vector<DroidProbe::MountInfo> mounts;

    if (!get_mounts(mounts)) {
        return nullptr;
    }

    jclass mount_info_class = env->FindClass("com/guozilu/droidprobe/utils/MountInfo");
    if (mount_info_class == nullptr) {
        return nullptr;
    }

    jmethodID constructor = env->GetMethodID(
        mount_info_class,
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V"
    );
    if (constructor == nullptr) {
        return nullptr;
    }

    jobjectArray result =env->NewObjectArray(
        static_cast<jsize>(mounts.size()),
        mount_info_class,
        nullptr
    );
    if (result == nullptr) {
        return nullptr;
    }

    jclass string_class = env->FindClass("java/lang/String");
    if (string_class == nullptr) {
        return nullptr;
    }

    // 在 C/C++ native 层通过 JNI 创建 Java 对象时，JNI 会自动为这些对象创建一个局部引用
    // JVM 为每个 Native 线程维护的局部引用表是有上限的（通常只有 512 个）
    // 因为这里是循环，所以每当引用不需要了就要立刻释放，否则会抛出异常导致崩溃
    for (size_t i = 0; i < mounts.size(); ++i) {
        const DroidProbe::MountInfo& mount_info = mounts[i];

        // 创建 JNI 中的 mount_point，mount_options，filesystem_type，mount_source，super_options 对象
        jstring mount_point = env->NewStringUTF(mount_info.mount_point.c_str());
        jstring mount_options = env->NewStringUTF(mount_info.mount_options.c_str());
        jstring filesystem_type = env->NewStringUTF(mount_info.filesystem_type.c_str());
        jstring mount_source = env->NewStringUTF(mount_info.mount_source.c_str());
        jstring super_options = env->NewStringUTF(mount_info.super_options.c_str());

        if (mount_point == nullptr ||
            mount_options == nullptr ||
            filesystem_type == nullptr ||
            mount_source == nullptr ||
            super_options == nullptr) {
            return nullptr;
        }

        // 创建 JNI MountInfo 对象
        jobject object = env->NewObject(
            mount_info_class,
            constructor,
            mount_point,
            mount_options,
            filesystem_type,
            mount_source,
            super_options
        );

        // 释放 JNI 对象的局部引用
        env->DeleteLocalRef(mount_point);
        env->DeleteLocalRef(mount_options);
        env->DeleteLocalRef(filesystem_type);
        env->DeleteLocalRef(mount_source);
        env->DeleteLocalRef(super_options);

        if (object == nullptr) {
            return nullptr;
        }

        // 把 JNI MountInfo 对象加入到数组中
        env->SetObjectArrayElement(result,static_cast<jsize>(i),object);

        // 释放 JNI MountInfo 对象的局部引用
        env->DeleteLocalRef(object);
    }

    return result;
}
