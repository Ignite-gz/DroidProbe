//
// Created by ignite on 9/28/26.
//

#include <jni.h>
#include "kernel_su_detector.h"
#include "native_detector_utils.h"
#include <droid_probe_log.h>

extern "C"
JNIEXPORT jint JNICALL
Java_com_guozilu_droidprobe_root_KernelSuDetector_nativeScan(JNIEnv *env, jobject thiz,
    jobject evidences) {
    // TODO: implement nativeScan()
    using namespace DroidProbe::Root;
    if (evidences == nullptr) {
        DroidProbe::Log::error(__FUNCTION__, "%s", "List<DetectionEvidence> evidences is null!");
        return 0;
    }

    try {
        NativeScanResult result = KernelSuScanner::Scan();

        if (!AppendJavaEvidences(env, evidences, result.evidences)) {
            // 若 Java 异常仍处于 pending 状态，则保留异常，由 JNI 返回路径传回 Java
            return kNativeScanError;
        }

        // 有阳性证据时优先返回分值，即使扫描器随后遇到局部错误。
        // 扫描完整性由证据说明；Java 层对阳性分值正常映射风险等级。
        if (result.risk_score > 0) {
            return static_cast<jint>(result.risk_score);
        }

        if (result.state == NativeScanState::ERROR) {
            return kNativeScanError;
        }

        if (result.state == NativeScanState::INCOMPLETE) {
            return kNativeScanIncomplete;
        }

        return 0;
    }
    catch (...) {
        // 不允许 C++ 异常跨越 JNI 边界。
        return kNativeScanError;
    }
}
