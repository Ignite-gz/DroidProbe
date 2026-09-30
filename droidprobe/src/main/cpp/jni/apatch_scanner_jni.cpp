//
// Created by ignite on 9/30/26.
//

#include <jni.h>
#include <vector>
#include "apatch_scanner.h"

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
JNIEXPORT jobject JNICALL
Java_com_guozilu_droidprobe_root_APatchDetector_nativeScanAPatch(JNIEnv *env, jobject thiz,
                                                                 jint android_api_level) {
    // TODO: implement nativeScanAPatch()
    try {
        // 执行纯 C++ 的 APatch 检测逻辑。
        const DroidProbe::Root::APatchScanResult result =
            DroidProbe::Root::APatchScanner::Scan(
                static_cast<int>(android_api_level)
            );

        // 找到 Java String 类，用于创建三个 String[] 证据数组。
        jclass string_class = env->FindClass(kStringClass);

        if (string_class == nullptr || env->ExceptionCheck()) {
            // FindClass 失败时清理异常，避免异常跨 JNI 边界继续传播。
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }

            return nullptr;
        }

        // 将 C++ evidence 转换成 Java 能理解的三个平行数组。
        std::vector<std::string> rule_names;
        std::vector<std::string> targets;
        std::vector<std::string> details;

        // 预分配容量，减少 vector 扩容次数。
        rule_names.reserve(result.evidences.size());
        targets.reserve(result.evidences.size());
        details.reserve(result.evidences.size());

        // 提取每条 Native evidence 的三个字符串字段。
        for (const auto& evidence : result.evidences) {
            rule_names.push_back(evidence.rule);
            targets.push_back(evidence.target);
            details.push_back(evidence.detail);
        }

        // 创建 ruleName[]。
        jobjectArray rule_array =
            NewStringArray(env, string_class, rule_names);

        // 创建 target[]。
        jobjectArray target_array =
            NewStringArray(env, string_class, targets);

        // 创建 detail[]。
        jobjectArray detail_array =
            NewStringArray(env, string_class, details);

        // string_class 已经完成使命，可以删除局部引用。
        env->DeleteLocalRef(string_class);

        // 任意数组创建失败都不能继续实例化 Java Result。
        if (rule_array == nullptr || target_array == nullptr || detail_array == nullptr) {
            if (rule_array != nullptr) {
                env->DeleteLocalRef(rule_array);
            }
            if (target_array != nullptr) {
                env->DeleteLocalRef(target_array);
            }
            if (detail_array != nullptr) {
                env->DeleteLocalRef(detail_array);
            }

            return nullptr;
        }

        // 查找 Java 内部类 APatchDetector$APatchNativeResult。
        jclass result_class = env->FindClass(kNativeResultClass);

        if (result_class == nullptr || env->ExceptionCheck()) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }

            env->DeleteLocalRef(rule_array);
            env->DeleteLocalRef(target_array);
            env->DeleteLocalRef(detail_array);
            return nullptr;
        }

        // 获取五参数构造函数：score、state、三个 String[]。
        jmethodID constructor = env->GetMethodID(
            result_class,
            "<init>",
            kNativeResultConstructor
        );

        if (constructor == nullptr || env->ExceptionCheck()) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }

            env->DeleteLocalRef(result_class);
            env->DeleteLocalRef(rule_array);
            env->DeleteLocalRef(target_array);
            env->DeleteLocalRef(detail_array);
            return nullptr;
        }

        // 创建 Java APatchNativeResult 对象。
        jobject java_result = env->NewObject(
            result_class,
            constructor,
            static_cast<jint>(result.max_score),
            static_cast<jint>(result.state),
            rule_array,
            target_array,
            detail_array
        );

        // 所有 JNI 局部引用在返回前释放，避免长期扫描造成 Local Reference 累积。
        env->DeleteLocalRef(result_class);
        env->DeleteLocalRef(rule_array);
        env->DeleteLocalRef(target_array);
        env->DeleteLocalRef(detail_array);

        // NewObject 可能抛出 Java 异常；这种情况下返回 null，由 Java 层转为 UNKNOWN。
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            return nullptr;
        }

        return java_result;
    } catch (...) {
        // 最后一道边界：任何 C++ 异常都不能跨越 JNI 边界。
        // 这里不主动向 Java 抛自定义异常，而是返回 null，让检测器进入 UNKNOWN。
        return nullptr;
    }
}