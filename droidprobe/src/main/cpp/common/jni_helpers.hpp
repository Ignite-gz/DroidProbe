//
// Created by ignite on 10/3/26.
//

#ifndef DROIDPROBE_JNI_HELPERS_HPP
#define DROIDPROBE_JNI_HELPERS_HPP

#include <jni.h>
#include <string>
#include <vector>
#include "droid_probe_log.h"

namespace DroidProbe {
    /**
    * @brief 创建 Java String
    * @param env JNIEnv
    * @param value 要转化的字符串
    * @return 如果 env 为 nullptr 则返回 nullptr，否则返回对应的 jstring
    */
    jstring NewJavaString(JNIEnv* env, const std::string& value);

    /**
    * @brief 创建 Java String
    * @param env JNIEnv
    * @param value 要转化的字符串
    * @return 如果 env 为 nullptr 则返回 nullptr，否则返回对应的 jstring
    */
    jstring NewJavaString(JNIEnv* env, const char* value);

    /**
    * @brief 将 C++ vector<string> 转换成 Java String[]。
    * @param env JNIEnv
    * @param values C++ vector<string>
    * @return 如果出错了返回 nullptr，否则返回 values 对应的 Java String[]
    */
    jobjectArray NewStringArray(JNIEnv* env, const std::vector<std::string>& values);

    /**
    * 将 C++ vector<_Ty> 转换成 Java _Ty[]。
    * @tparam _Ty java_class 对应的 C++ 的类型，
    * @param env JNIEnv
    * @param java_class_name Java Class 的 C style 字符串，一个类似于 "java/lang/String" 的字符串
    * @param values 要转化的 C++ vector<_Ty>
    * @param converter 将 C++ 的 _Ty 数据转化为 Java 数据的函数，格式大概为 jobject converter(JNIENV* env, const _Ty& value)
    * @return 如果出错了返回 nullptr，否则返回 values 对应的 Java _Ty[]
    */
    template<typename _Ty, typename ConverterFunction>
    jobjectArray NewJavaArray(JNIEnv* env, const char* java_class_name, const std::vector<_Ty>& values,
                              ConverterFunction converter) {
        if (env == nullptr) {
            DroidProbe::Log::error(__FUNCTION__, "JNIENV* env == nullptr!!!");
            return nullptr;
        }

        jclass java_class = env->FindClass(java_class_name);
        if (java_class == nullptr) {
            DroidProbe::Log::error(__FUNCTION__, "env 查找不到指定的 java_class_name");
            return nullptr;
        }

        // 创建与证据数量相等的 Java _Ty 数组。
        jobjectArray array = env->NewObjectArray(
            static_cast<jsize>(values.size()),
            java_class,
            nullptr
        );

        // 后面用不着 java_class 了，将其释放
        env->DeleteLocalRef(java_class);

        if (array == nullptr) {
            return nullptr;
        }

        // 将每条 Native _Ty 转换成 Java _Ty 并放入数组
        for (jsize i = 0; i < static_cast<jsize>(values.size()); ++i) {
            jobject value = converter(env, values[static_cast<size_t>(i)]);

            if (value == nullptr) {
                // 执行 converter 失败时释放已经创建的数组，让 Java 侧收到 null
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
    } /* NewJavaArray */
} // namespace DroidProbe

#endif //DROIDPROBE_JNI_HELPERS_HPP
