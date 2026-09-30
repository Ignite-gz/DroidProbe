//
// Created by ignite on 9/30/26.
//

#include <jni.h>
#include <vector>
#include "apatch_scanner.h"
#include "droid_probe_log.h"

namespace {

    /**
     * Java 层 APatchDetector$APatchNativeResult 的签名。
     *
     * Java 中的构造函数为：
     * APatchNativeResult(int maxScore,
     *                    int scanState,
     *                    String[] ruleNames,
     *                    String[] targets,
     *                    String[] details)
     */
    constexpr const char* kNativeResultClass =
        "com/guozilu/droidprobe/root/APatchDetector$APatchNativeResult";

    constexpr const char* kNativeResultConstructor =
        "(II[Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;)V";

    constexpr const char* kStringClass = "java/lang/String";

    /**
     * 创建 Java String；Native 字符串如果为空则仍然返回空字符串，而不是 null。
     * 这样 DetectionEvidence 在 Java 层更容易处理。
     */
    jstring NewJavaString(
        JNIEnv* env,
        const std::string& value) {
        if (env == nullptr) {
            return nullptr;
        }

        return env->NewStringUTF(value.c_str());
    }

    /**
     * 将 C++ vector<string> 转换成 Java String[]。
     */
    jobjectArray NewStringArray(
        JNIEnv* env,
        jclass string_class,
        const std::vector<std::string>& values) {
        if (env == nullptr || string_class == nullptr) {
            return nullptr;
        }

        // 创建与证据数量相等的 String 数组。
        jobjectArray array = env->NewObjectArray(
            static_cast<jsize>(values.size()),
            string_class,
            nullptr
        );

        if (array == nullptr) {
            return nullptr;
        }

        // 将每条 Native 字符串转换成 Java String 并放入数组。
        for (jsize i = 0; i < static_cast<jsize>(values.size()); ++i) {
            jstring value = NewJavaString(env, values[static_cast<size_t>(i)]);

            if (value == nullptr) {
                // NewStringUTF 失败时释放已经创建的数组，让 Java 侧收到 null。
                env->DeleteLocalRef(array);
                return nullptr;
            }

            env->SetObjectArrayElement(array, i, value);
            env->DeleteLocalRef(value);

            // SetObjectArrayElement 本身可能产生 OutOfMemory 等 Java 异常。
            if (env->ExceptionCheck()) {
                env->DeleteLocalRef(array);
                return nullptr;
            }
        }

        return array;
    }

} // namespace

extern "C"
JNIEXPORT jint JNICALL
Java_com_guozilu_droidprobe_root_APatchDetector_nativeScan(JNIEnv *env, jobject thiz,
    jobject evidences) {
    // TODO: implement nativeScan()
    using namespace DroidProbe::Root;
    if (evidences == nullptr) {
        DroidProbe::Log::error(__FUNCTION__, "%s", "List<DetectionEvidence> evidences is null!");
        return 0;
    }

    try {
        NativeScanResult result = APatchScanner::Scan();

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
