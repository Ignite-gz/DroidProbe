//
// Created by ignite on 9/30/26.
//

#ifndef DROIDPROBE_NATIVE_DETECTOR_UTILS_H
#define DROIDPROBE_NATIVE_DETECTOR_UTILS_H

#include <jni.h>
#include <vector>
#include <fcntl.h>
#include <unistd.h>

namespace DroidProbe {
    namespace Root {
        /**
         * Native 扫描状态。
         *
         * <p>将“未发现特征”和“没有能力完成检测”分开，防止把权限不足、文件不可读
         * 或解析失败错误解释为设备不存在这种 root 的方式。</p>
         */
        enum class NativeScanState {
            /** 扫描流程执行完成，当前可用数据源均已处理。 */
            COMPLETE,

            /** 至少一个重要数据源不可访问、读取失败或扫描受限。 */
            INCOMPLETE,

            /** 扫描器内部发生不可恢复错误。 */
            ERROR
        };

        /** 路径访问结果。 */
        enum PathAccessResult {
            PathNotAccessible,
            PathNotFound = 0,
            PathExists = 1
        };

        /**
         * Native 层检测证据的数据结构。
         *
         * <p>该结构不依赖 JNI，负责在 Native 探针与 JNI 桥接层之间传递结果。
         * JNI 桥接层会在扫描完成后统一将其转换为 Java DetectionEvidence 对象。</p>
         */
        struct NativeEvidence {
            std::string type;
            std::string value;
            std::string description;
        };

        /**
        * native 扫描汇总结果。
        *
        * <p>risk_score 表示当前命中证据中的最高分值，不做无条件累加。
        * evidences 保存每一项独立证据，供 Java 层展示、归档或进行更高层的融合判断。</p>
        */
        struct NativeScanResult {
            int risk_score = 0;
            NativeScanState state = NativeScanState::COMPLETE;
            std::vector<NativeEvidence> evidences;
        };

        /**
         * 有界文件读取状态。
         *
         * <p>procfs 是动态伪文件系统，普通文件的 seek/size 语义不一定适用，因而使用
         * read() 顺序读取，并显式区分读取失败与读取被上限截断。</p>
         */
        struct ReadResult {
            bool opened = false;
            bool completed = false;
            bool truncated = false;
            int error_number = 0;
            std::string content;
        };

        /**
         * 与 Java <Abstract>NativeDetector 中的 native 状态码保持一致。
         * 非负数表示最高检测分值，负数表示扫描状态。
         */
        constexpr jint kNativeScanError = -1;
        constexpr jint kNativeScanIncomplete = -2;

        /** procfs 文件读取上限，避免异常环境下无界读取。 */
        constexpr size_t kMaxProcFileBytes = 16U * 1024U * 1024U;
        constexpr size_t kMaxEvidencePerSource = 8U;
        constexpr size_t kReadBufferSize = 4096U;

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
        bool HasPendingJavaException(JNIEnv* env);

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
            const NativeEvidence& evidence);

        /**
         * 将 Native 扫描结果的证据列表批量写入 Java List。
         *
         * <p>List 类、add 方法、DetectionEvidence 类和构造函数只解析一次，
         * 不在每条证据循环中重复 FindClass/GetMethodID。</p>
         */
        bool AppendJavaEvidences(JNIEnv* env, jobject evidence_list,
            const std::vector<NativeEvidence>& evidences);

        /**
         * 使用 POSIX open/read 有界读取文件。
         *
         * @param path 待读取路径
         * @param max_bytes 最大读取字节数
         * @return 包含读取状态、errno 和文本内容的结果
         */
        ReadResult ReadTextFile(const char* path, size_t max_bytes);

        /**
        * 使用 POSIX open/read 有界读取文件。
        * @param path 待读取路径
        * @param out 用于存储读取的文本内容
        * @param max_bytes 最大读取字节数
        * @return 正常读取完成返回 true，否则返回 false
        */
        bool ReadTextFile(const char* path, std::string& out, size_t max_bytes);

        /**
         * 将检测证据追加到结果中，并更新最高命中分值。
         *
         * <p>同一类型和值的证据只保留一次；多项证据不累加，而是取最高分，避免相关
         * 信号被重复计算后夸大风险等级。</p>
         */
        void AddEvidence(NativeScanResult& result, int score, const char* type,
            const std::string& value, const char* description);

        /**
         * 将数据源不可观测或读取不完整的情况作为诊断证据记录。
         *
         * <p>可访问性问题本身不是 KernelSU 证据，因此 score 固定为 0；它只会影响
         * 最终扫描状态，使“未发现”与“无法确认”能够被区分。</p>
         */
        void AddScanLimitation(NativeScanResult& result, const char* source,
            const char* reason);

        /**
         * 判断 errno 是否表示路径不可访问。
         * EACCES/EPERM 代表当前调用者缺少访问权限，不代表目标不存在或系统已被篡改。
         */
        bool IsPermissionError(int error_number);

        /**
         * 从类似 5.10.177-android... 的字符串中解析 major/minor。
         */
        bool ParseKernelRelease(const char* release, int& major, int& minor);

        /**
         * 将 kernel version (major, minor) 映射成一个可比较的二元版本关系。
         */
        int CompareKernelVersion(int major, int minor, int other_major, int other_minor);

        /**
        * 检查路径上的文件的存在情况
        * @param path 文件的路径
        * @return 如果文件存在返回 PathAccessResult::PathExists
        * 如果文件不存在则返回 PathAccessResult::PathNotFound
        * 其它情况，如权限问题等返回 PathAccessResult::PathNotAccessible
        */
        int CheckPathExists(const char* path);

        /** 判断 text 是不是数字 */
        bool IsNumeric(const char* text);

        /** 去除字符串首尾的空字符 */
        std::string Trim(const std::string& value);

        /**
        * 获取进程名
        * @param pid 进程的 pid
        * @param name 用于存储获取到的进程名
        * @return 获取成功返回 true，否则返回 false
        */
        bool ReadProcessName(int pid, std::string& name);
    }
}

#endif // DROIDPROBE_NATIVE_DETECTOR_UTILS_H
