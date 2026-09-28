//
// Created by ignite on 9/28/26.
//

#include <jni.h>
#include "kernel_su_detector.h"

namespace {
    /**
     * 与 Java KernelSuDetector 中的 native 状态码保持一致。
     * 非负数表示最高检测分值，负数表示扫描状态。
     */
    constexpr jint kNativeScanError = -1;
    constexpr jint kNativeScanIncomplete = -2;

    /**
     * Java DetectionEvidence 的全限定类名。
     * 如果项目调整 core 包路径，需要同步修改此处。
     */
    constexpr const char* kDetectionEvidenceClassName =
        "com/guozilu/droidprobe/core/DetectionEvidence";

    /**
     * Java DetectionEvidence(String type, String value, String description) 构造函数签名。
     * 如果 DetectionEvidence 的构造参数发生变化，需要同步更新 JNI 签名。
     */
    constexpr const char* kDetectionEvidenceConstructorSignature =
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V";

    /**
     * 检查 JNI 调用是否产生待处理异常。
     *
     * <p>这里不主动清除 Java 异常。发生异常时将停止继续访问 JNI 对象，
     * 让异常沿原调用链返回 Java 层，由上层 AbstractDetector 负责隔离。</p>
     */
    bool HasPendingJavaException(JNIEnv* env) {
        return env == nullptr || env->ExceptionCheck() == JNI_TRUE;
    } /* HasPendingJavaException */

    /**
     * 将一个 Native 证据转换为 Java DetectionEvidence，并追加到调用者传入的 List。
     *
     * <p>每次只创建少量局部引用，添加完成后立即释放，避免在多条证据时耗尽
     * JNI Local Reference Table。所有 JNI 创建和调用操作都会检查异常状态。</p>
     *
     * @return 成功追加时返回 true；JNI 失败时返回 false
     */
    bool AppendJavaEvidence(JNIEnv* env, jobject evidence_list, jmethodID list_add_method,
                            jclass evidence_class, jmethodID evidence_constructor,
                            const DroidProbe::Root::KernelSuEvidence& evidence) {
        if (env == nullptr || evidence_list == nullptr || list_add_method == nullptr
            || evidence_class == nullptr || evidence_constructor == nullptr) {
            return false;
        }

        jstring type = env->NewStringUTF(evidence.type.c_str());
        if (type == nullptr || HasPendingJavaException(env)) {
            if (type != nullptr) {
                env->DeleteLocalRef(type);
            }
            return false;
        }

        jstring value = env->NewStringUTF(evidence.value.c_str());
        if (value == nullptr || HasPendingJavaException(env)) {
            env->DeleteLocalRef(type);
            if (value != nullptr) {
                env->DeleteLocalRef(value);
            }
            return false;
        }

        jstring description = env->NewStringUTF(evidence.description.c_str());
        if (description == nullptr || HasPendingJavaException(env)) {
            env->DeleteLocalRef(type);
            env->DeleteLocalRef(value);
            if (description != nullptr) {
                env->DeleteLocalRef(description);
            }
            return false;
        }

        jobject java_evidence = env->NewObject(
            evidence_class,
            evidence_constructor,
            type,
            value,
            description
        );

        if (java_evidence == nullptr || HasPendingJavaException(env)) {
            env->DeleteLocalRef(type);
            env->DeleteLocalRef(value);
            env->DeleteLocalRef(description);
            if (java_evidence != nullptr) {
                env->DeleteLocalRef(java_evidence);
            }
            return false;
        }

        env->CallBooleanMethod(evidence_list, list_add_method, java_evidence);
        const bool success = !HasPendingJavaException(env);

        env->DeleteLocalRef(java_evidence);
        env->DeleteLocalRef(description);
        env->DeleteLocalRef(value);
        env->DeleteLocalRef(type);

        return success;
    } /* AppendJavaEvidence */

    /**
     * 将 Native 扫描结果的证据列表批量写入 Java List。
     *
     * <p>List 类、add 方法、DetectionEvidence 类和构造函数只解析一次，
     * 不在每条证据循环中重复 FindClass/GetMethodID。</p>
     */
    bool AppendJavaEvidences(JNIEnv* env, jobject evidence_list,
                             const std::vector<DroidProbe::Root::KernelSuEvidence>& evidences) {
        if (env == nullptr || evidence_list == nullptr) {
            return false;
        }

        jclass list_class = env->GetObjectClass(evidence_list);
        if (list_class == nullptr || HasPendingJavaException(env)) {
            if (list_class != nullptr) {
                env->DeleteLocalRef(list_class);
            }
            return false;
        }

        jmethodID list_add_method = env->GetMethodID(
            list_class,
            "add",
            "(Ljava/lang/Object;)Z"
        );

        if (list_add_method == nullptr || HasPendingJavaException(env)) {
            env->DeleteLocalRef(list_class);
            return false;
        }

        jclass evidence_class = env->FindClass(kDetectionEvidenceClassName);
        if (evidence_class == nullptr || HasPendingJavaException(env)) {
            env->DeleteLocalRef(list_class);
            if (evidence_class != nullptr) {
                env->DeleteLocalRef(evidence_class);
            }
            return false;
        }

        jmethodID evidence_constructor = env->GetMethodID(
            evidence_class,
            "<init>",
            kDetectionEvidenceConstructorSignature
        );

        if (evidence_constructor == nullptr || HasPendingJavaException(env)) {
            env->DeleteLocalRef(evidence_class);
            env->DeleteLocalRef(list_class);
            return false;
        }

        bool success = true;
        for (const auto& evidence : evidences) {
            if (!AppendJavaEvidence(
                env,
                evidence_list,
                list_add_method,
                evidence_class,
                evidence_constructor,
                evidence)) {
                success = false;
                break;
            }
        }

        env->DeleteLocalRef(evidence_class);
        env->DeleteLocalRef(list_class);
        return success;
    } /* AppendJavaEvidences */
} // namespace


extern "C"
JNIEXPORT jint JNICALL
Java_com_guozilu_droidprobe_root_KernelSuDetector_nativeScan(JNIEnv *env, jobject thiz,
    jobject evidences) {
    // TODO: implement nativeScan()
    try {
        DroidProbe::Root::KernelSuScanResult result = DroidProbe::Root::KernelSuScanner::Scan();

        if (!AppendJavaEvidences(env, evidences, result.evidences)) {
            // 若 Java 异常仍处于 pending 状态，则保留异常，由 JNI 返回路径传回 Java
            return kNativeScanError;
        }

        // 有阳性证据时优先返回分值，即使扫描器随后遇到局部错误。
        // 扫描完整性由证据说明；Java 层对阳性分值正常映射风险等级。
        if (result.risk_score > 0) {
            return static_cast<jint>(result.risk_score);
        }

        if (result.state == DroidProbe::Root::KernelSuScanState::ERROR) {
            return kNativeScanError;
        }

        if (result.state == DroidProbe::Root::KernelSuScanState::INCOMPLETE) {
            return kNativeScanIncomplete;
        }

        return 0;
    }
    catch (...) {
        // 不允许 C++ 异常跨越 JNI 边界。
        return kNativeScanError;
    }
}
