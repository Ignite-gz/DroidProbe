//
// Created by ignite on 9/28/26.
//

#ifndef DROIDPROBE_KERNEL_SU_DETECTOR_H
#define DROIDPROBE_KERNEL_SU_DETECTOR_H

#include <string>
#include <vector>
#include "native_detector_utils.h"

namespace DroidProbe {
    namespace Root {

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
             * 执行 KernelSU 多维度特征扫描。
             *
             * <p>扫描仅采集当前进程能够访问的数据，不执行 su，不修改系统状态，也不尝试
             * 调用可能改变管理器身份、授予 Root 权限或修改内核配置的 KernelSU 命令。</p>
             *
             * <p>探测数据源包括：</p>
             * <ol>
             *     <li>uname：记录内核版本，作为兼容性上下文。</li>
             *     <li>/proc/modules：识别以模块形式加载、且名称精确匹配的候选条目。</li>
             *     <li>/proc/net/unix：仅匹配明确列出的候选 Socket 名称。</li>
             *     <li>已知文件路径：只在 stat 成功时记录存在，不对 ENOENT/EACCES 作越权推断。</li>
             *     <li>/proc/kallsyms：在可读取时解析符号名列，查找 KSU 前缀特征。</li>
             * </ol>
             *
             * <p>风险分值只取最高命中证据，不累加不同来源的弱信号。任何关键数据源不可读、
             * 读取被截断或解析无法完成时，若没有阳性证据，结果状态为 INCOMPLETE，交由
             * Java 层映射为 UNKNOWN。</p>
             *
             * @return Native 扫描结果
             */
            static DroidProbe::Root::NativeScanResult Scan();
        };

    } // namespace Root
} // namespace DroidProbe

#endif // DROIDPROBE_KERNEL_SU_DETECTOR_H
