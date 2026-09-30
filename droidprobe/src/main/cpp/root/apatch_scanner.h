//
// Created by ignite on 9/30/26.
//

#ifndef DROIDPROBE_APATCH_SCANNER_H
#define DROIDPROBE_APATCH_SCANNER_H

#include <string>
#include <vector>

namespace DroidProbe {
    namespace Root {

        /**
         * APatch Native 扫描最终状态。
         *
         * 注意：
         * CLEAN 表示本次扫描中的可观察探针全部完成，并且没有发现阳性特征；
         * 它不等价于“设备绝对没有 APatch”。
         */
        enum class APatchScanState {
            CLEAN = 0,
            DETECTED = 1,
            UNKNOWN = 2,
            UNSUPPORTED = 3,
            ERROR = 4,
        };

        /**
         * 单条 Native 检测证据。
         *
         * Native 层不直接创建 Java DetectionEvidence，而是在这里保存普通 C++ 字符串，
         * 最后由 JNI 层统一转换成 Java 对象。这样可以把“检测逻辑”和“JNI 对象管理”彻底分离。
         */
        struct APatchEvidence {
            /** 当前证据的启发式最高风险分值。 */
            int score = 0;
            /** 规则名称，例如 APATCH_PACKAGE_CONFIG。 */
            std::string rule;
            /** 被观察的目标，例如 /data/adb/ap/package_config。 */
            std::string target;
            /** 面向调用者的人类可读解释。 */
            std::string detail;
        };

        /**
         * APatch Native 扫描结果。
         */
        struct APatchScanResult {
            /** 当前扫描状态。 */
            APatchScanState state = APatchScanState::UNKNOWN;
            /** 所有证据中最高的有效分值。 */
            int max_score = 0;
            /** uname() 读取出的 Linux 内核主版本。 */
            int kernel_major = -1;
            /** uname() 读取出的 Linux 内核次版本。 */
            int kernel_minor = -1;
            /** 当前系统的 Android API Level，由 Java 层传入。 */
            int android_api_level = -1;
            /** Native 检测是否发现了可完整观察的 /proc 基础信息。 */
            bool proc_observable = false;
            /** Native 检测是否至少访问到了关键文件系统观察点。 */
            bool filesystem_observable = false;
            /** 扫描过程中产生的证据列表。 */
            std::vector<APatchEvidence> evidences;
        };

        /**
         * APatch 核心扫描器。
         *
         * 检测策略故意不依赖 su/kp/apd 的固定文件名作为唯一条件，而是从：
         * 1. 内核版本 / 架构；
         * 2. APatch 官方已知用户空间结构；
         * 3. package_config 等 APatch 配置文件；
         * 4. APatch / KernelPatch 进程线索；
         * 5. /proc/kallsyms 中经过源码验证的 KernelPatch 符号；
         * 6. /proc/net/unix 的 APatch daemon 通信线索；
         * 7. mountinfo 中与 APatch 当前实现有关的路径；
         * 组合判断。
         *
         * 重要限制：
         * APatch 可以被主动修改、隐藏或重新构建，因此本类不能提供对抗“内核完全信任被破坏”
         * 场景的绝对检测保证。任何单一用户空间特征都只能作为证据，而不是绝对真值。
         */
        class APatchScanner final {
        public:
            /**
             * 执行全部 APatch 探针。
             *
             * @param android_api_level 当前 Android API Level。
             * @return 结构化 APatch 扫描结果。
             */
            static APatchScanResult Scan(int android_api_level);

        private:
            /** 添加一条证据，并自动维护最高分值。 */
            static void AddEvidence(
                APatchScanResult& result,
                int score,
                const char* rule,
                const std::string& target,
                const std::string& detail);

            /** 读取 uname() 并检查当前 Linux 内核是否处在官方声明的范围内。 */
            static bool AddKernelVersionContext(APatchScanResult& result);

            /**
             * 检测 APatch 稳定用户空间结构。
             *
             * 核心目标：/data/adb/ap/package_config、/data/adb/ap 等。
             *
             * 注意：/data/adb/ap 是比“/data/adb 是否可访问”更有价值的目标；
             * 不把 ENOENT 当作 SELinux 绕过证据，因为 ENOENT 只表示目标路径不存在。
             */
            static void CheckAPatchArtifacts(APatchScanResult& result);

            /** 检测 APatch / KernelPatch 用户空间 daemon 的进程痕迹。 */
            static void CheckUserSpaceProcesses(APatchScanResult& result);

            /**
             * 扫描 /proc/kallsyms。
             *
             * 不把“kallsyms 可读”本身视为 APatch 阳性；只有发现经过源码核对的
             * KernelPatch 特征符号时才增加较强证据。
             */
            static void CheckKernelSymbols(APatchScanResult& result);

            /**
             * 扫描 /proc/net/unix。
             *
             * 只有发现经源码 / 实机验证的 APatch 用户空间通信特征才计分；
             * “文件可读”本身只作为可观测性信息，不计 APatch 分值。
             */
            static void CheckUnixSockets(APatchScanResult& result);

            /**
             * 检查当前 mount namespace 中是否存在与 APatch 已知工作结构相关的挂载痕迹。
             * 这一项只做辅助证据，因为 APatch 当前与历史版本的挂载实现会发生变化。
             */
            static void CheckMountInfo(APatchScanResult& result);

            /** 读取小型文本文件；超出最大大小或发生错误时返回 false。 */
            static bool ReadTextFile(
                const char* path,
                std::string& out,
                size_t max_bytes);

            /** 检测路径是否存在，严格区分“存在”“不存在”“无法判断”。 */
            static int CheckPathExists(const char* path);

            /** 判断字符串是否为纯数字 PID。 */
            static bool IsNumeric(const char* text);

            /** 判断是否为 Android / Linux 常见的 APatch daemon 名称。 */
            static bool IsPotentialAPatchProcessName(const std::string& name);

            /** 从 /proc/<pid>/status 中读取指定字段。 */
            static bool ReadProcStatusField(
                int pid,
                const char* field,
                std::string& value);

            /** 读取 /proc/<pid>/cmdline 的第一个 argv。 */
            static bool ReadProcessName(int pid, std::string& name);
        };

    } // namespace Root
} // namespace DroidProbe

#endif // DROIDPROBE_APATCH_SCANNER_H
