//
// Created by ignite on 9/28/26.
//

#ifndef DROIDPROBE_KERNEL_SU_DETECTOR_H
#define DROIDPROBE_KERNEL_SU_DETECTOR_H

#include <string>
#include <vector>

namespace DroidProbe {
    namespace Root {

        /**
         * Native 层检测证据的数据结构。
         *
         * <p>该结构不依赖 JNI，负责在 Native 探针与 JNI 桥接层之间传递结果。
         * JNI 桥接层会在扫描完成后统一将其转换为 Java DetectionEvidence 对象。</p>
         */
        struct KernelSuEvidence {
            std::string type;
            std::string value;
            std::string description;
        };

        /**
         * Native 扫描状态。
         *
         * <p>将“未发现特征”和“没有能力完成检测”分开，防止把权限不足、文件不可读
         * 或解析失败错误解释为设备不存在 KernelSU。</p>
         */
        enum class KernelSuScanState {
            /** 扫描流程执行完成，当前可用数据源均已处理。 */
            COMPLETE,

            /** 至少一个重要数据源不可访问、读取失败或扫描受限。 */
            INCOMPLETE,

            /** 扫描器内部发生不可恢复错误。 */
            ERROR
        };

        /**
         * KernelSU 扫描汇总结果。
         *
         * <p>risk_score 表示当前命中证据中的最高分值，不做无条件累加。
         * evidences 保存每一项独立证据，供 Java 层展示、归档或进行更高层的融合判断。</p>
         */
        struct KernelSuScanResult {
            int risk_score = 0;
            KernelSuScanState state = KernelSuScanState::COMPLETE;
            std::vector<KernelSuEvidence> evidences;
        };

        /**
         * KernelSU Native 探针调度器。
         *
         * <p>类内只公开一个扫描入口。具体的 procfs、文件系统、内核符号和协议探测
         * 实现保留在 .cpp 的匿名命名空间中，避免将实现细节泄漏到其他模块。</p>
         *
         * <p>本模块以普通 Android 应用的权限为前提运行，不执行 su、不修改系统状态，
         * 不主动请求 Root，也不执行具有副作用的 KernelSU 管理命令。</p>
         */
        class KernelSuScanner final {
        public:
            /**
             * 执行一次完整的 KernelSU 特征扫描。
             *
             * @return 含最高命中分值、扫描状态及证据列表的结果对象
             */
            static KernelSuScanResult Scan();
        };

    } // namespace Root
} // namespace DroidProbe

#endif // DROIDPROBE_KERNEL_SU_DETECTOR_H
