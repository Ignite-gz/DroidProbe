//
// Created by ignite on 9/30/26.
//

#ifndef DROIDPROBE_APATCH_SCANNER_H
#define DROIDPROBE_APATCH_SCANNER_H

#include "native_detector_utils.h"

namespace DroidProbe {
    namespace Root {
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
            static DroidProbe::Root::NativeScanResult Scan();
        };
    } // namespace Root
} // namespace DroidProbe

#endif // DROIDPROBE_APATCH_SCANNER_H
