//
// Created by ignite on 9/29/26.
//

#include <jni.h>
#include <fstream>
#include <string>
#include "mount_info.h"
#include "jni_helpers.hpp"

static jobject NewJavaMountInfo(JNIEnv* env, const DroidProbe::Process::MountInfo& mount_info) {
    jclass mount_info_class = env->FindClass("com/guozilu/droidprobe/utils/MountInfo");
    jmethodID constructor = env->GetMethodID(
        mount_info_class,
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V"
    );

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
    env->DeleteLocalRef(mount_info_class);

    return object;
} /* NewJavaMountInfo */

extern "C"
JNIEXPORT jobjectArray JNICALL
Java_com_guozilu_droidprobe_utils_MountUtils_getMountsNative(JNIEnv *env, jclass clazz) {
    // TODO: implement getMountsNative()
    std::vector<DroidProbe::Process::MountInfo> mounts;

    if (!get_mounts(mounts)) {
        return nullptr;
    }

    return DroidProbe::NewJavaArray(
        env,
        "com/guozilu/droidprobe/utils/MountInfo",
        mounts,
        NewJavaMountInfo
    );
}

extern "C"
JNIEXPORT jobjectArray JNICALL
Java_com_guozilu_droidprobe_utils_MountUtils_readMounts(JNIEnv* env, jclass clazz) {
    // TODO: implement readMounts()
    std::ifstream fin("/proc/self/mounts", std::ios_base::in);
    std::vector<std::string> mounts;
    std::string line;
    while (getline(fin, line)) {
        mounts.push_back(std::move(line));
    }
    return DroidProbe::NewStringArray(env, mounts);
}

extern "C"
JNIEXPORT jobjectArray JNICALL
Java_com_guozilu_droidprobe_utils_MountUtils_readMountinfo(JNIEnv* env, jclass clazz) {
    // TODO: implement readMountinfo()
    std::ifstream fin("/proc/self/mountinfo", std::ios_base::in);
    std::vector<std::string> mountinfo;
    std::string line;
    while (getline(fin, line)) {
        mountinfo.push_back(std::move(line));
    }
    return DroidProbe::NewStringArray(env, mountinfo);
}

extern "C"
JNIEXPORT jobjectArray JNICALL
Java_com_guozilu_droidprobe_utils_MountUtils_readMountCommandLine(JNIEnv* env, jclass clazz) {
    // TODO: implement readMountCommandLine()
    FILE* pipe = popen("mount", "r");

    if (pipe == nullptr) {
        return nullptr;
    }

    std::vector<std::string> mount;
    char buffer[4096];
    while (fgets(buffer, sizeof buffer, pipe) != nullptr) {
        std::string line(buffer);
        if (!line.empty() && line.back() == '\n') {
            mount.push_back(std::move(line));
        }
    } /* while */

    return DroidProbe::NewStringArray(env, mount);
}
