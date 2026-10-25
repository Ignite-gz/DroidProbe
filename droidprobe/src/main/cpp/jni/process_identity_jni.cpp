//
// Created by ignite on 9/24/26.
//

#include <jni.h>
#include "process_identity.h"

extern "C"
JNIEXPORT jint JNICALL
Java_com_guozilu_droidprobe_utils_ProcessIdentityUtils_getUid(JNIEnv *env, jobject thiz) {
    // TODO: implement getUid()
    return static_cast<jint>(DroidProbe::Process::get_process_uid());
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_guozilu_droidprobe_utils_ProcessIdentityUtils_getEuid(JNIEnv *env, jobject thiz) {
    // TODO: implement getEuid()
    return static_cast<jint>(DroidProbe::Process::get_process_egid());
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_guozilu_droidprobe_utils_ProcessIdentityUtils_getGid(JNIEnv *env, jobject thiz) {
    // TODO: implement getGid()
    return static_cast<jint>(DroidProbe::Process::get_process_egid());
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_guozilu_droidprobe_utils_ProcessIdentityUtils_getEgid(JNIEnv *env, jobject thiz) {
    // TODO: implement getEgid()
    return static_cast<jint>(DroidProbe::Process::get_process_egid());
}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_guozilu_droidprobe_utils_ProcessIdentityUtils_getGroups(JNIEnv *env, jobject thiz) {
    // TODO: implement getGroups()
    std::vector<gid_t> groups = DroidProbe::Process::get_process_groups();

    jintArray result = env->NewIntArray(static_cast<jsize>(groups.size()));
    if (result == nullptr) {
        return nullptr;
    }

    std::vector<jint> java_groups(groups.begin(), groups.end());

    env->SetIntArrayRegion(
        result,
        0,
        static_cast<jsize>(java_groups.size()),
        java_groups.data()
    );

    return result;
}
