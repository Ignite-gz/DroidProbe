//
// Created by ignite on 9/28/26.
//

#include <jni.h>
#include "kernel_su_detector.h"

extern "C"
JNIEXPORT jint JNICALL
Java_com_guozilu_droidprobe_root_KernelSuDetector_nativeScan(JNIEnv *env,
    jobject thiz, jobject evidences) {
    // TODO: implement nativeScan()
    return DroidProbe::KernelSuScanner::ScanAndReport(env, evidences);
}
