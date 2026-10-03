//
// Created by ignite on 9/28/26.
//

#include "kernel_su_detector.h"
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <sys/stat.h>
#include <sstream>
#include <sys/utsname.h>
#include <sys/prctl.h>

namespace {
    /**
     * KernelSU 相关候选路径。
     *
     * <p>这些路径用于识别文件系统中可见的组件痕迹，不代表 KernelSU 的稳定 ABI。
     * 其中 /data/adb/ksud 是上游 KernelSU 用户态守护程序常见路径；allowlist 的存储路径、
     * 安装布局以及是否对普通应用可见，会随版本、分支和 ROM 配置发生变化。</p>
     *
     * <p>检查结果只表示 stat() 成功、当前应用能够读取该路径的元数据；绝不能将
     * ENOENT 解读为权限绕过，也不能把 EACCES 当成设备干净的证明。</p>
     */
    constexpr const char* kKsuPaths[] = {
        "/data/adb/ksud",
        "/data/adb/ksu",
        "/data/adb/ksu/.allowlist"
    };

    /**
     * /proc/net/unix 中可能出现的候选名称。
     *
     * <p>抽象 Unix Socket 名称不是 KernelSU 的稳定公开接口。这里仅保留原型阶段
     * 使用的候选字符串，并将其作为中低置信度线索；发布前必须针对目标 KernelSU
     * 版本实测确认。若目标版本不使用这些名称，应更新或禁用此候选列表。</p>
     */
    constexpr const char* kCandidateSocketNames[] = {
        "@ksud",
        "@kernelsu"
    };

    /**
     * 仅对精确的候选内核模块名进行匹配，避免在任意模块描述中做宽泛子串搜索。
     * KernelSU 也可能以内建方式集成，因此没有模块条目不代表不存在 KernelSU。
     */
    constexpr const char* kCandidateModuleNames[] = {
        "kernelsu",
        "ksu"
    };

    /** 每个探针的分值是启发式优先级，不是概率或统计置信度。 */
    constexpr int kScoreKsuModule = 80;
    constexpr int kScoreKsuKernelSymbol = 85;
    constexpr int kScoreKsuPath = 60;
    constexpr int kScoreCandidateSocket = 50;

    /**
     * 检查已知 KernelSU 文件系统路径。
     *
     * <p>仅当 stat() 成功时报告“路径存在”。ENOENT 只表示路径当前不可解析，
     * 不作风险加分；EACCES/EPERM 表示无法判断路径是否存在，扫描状态记为不完整。</p>
     */
    void CheckKsuPaths(DroidProbe::Root::NativeScanResult& result) {
        for (const char* path : kKsuPaths) {
            struct stat file_status{};
            errno = 0;

            if (stat(path, &file_status) == 0) {
                AddEvidence(
                    result,
                    kScoreKsuPath,
                    "KSU_PATH_EXISTS",
                    path,
                    "发现候选 KernelSU 路径且当前进程能够读取其元数据；"
                    "该路径可能是安装或残留痕迹，不能单独证明内核功能正在运行"
                );
                continue;
            }

            const int error_number = errno;
            if (DroidProbe::Root::IsPermissionError(error_number)) {
                AddScanLimitation(
                    result,
                    path,
                    "当前应用无权检查该候选路径，无法判断其是否存在；"
                    "权限拒绝属于常见系统隔离行为，不作为 Root 阳性证据"
                );
            }
            else if (error_number != ENOENT) {
                AddScanLimitation(
                    result,
                    path,
                    "检查候选路径时发生非预期文件系统错误，当前路径状态无法确认"
                );
            }
        }
    } /* CheckKsuPaths */

    /**
     * 从 /proc/modules 中识别精确匹配的 KernelSU 模块名。
     *
     * <p>/proc/modules 只列出作为可加载模块呈现的模块。KernelSU 若以内核源码
     * 内建方式编译，可能不会出现在这里；因此无命中不是排除结论。</p>
     */
    void CheckProcModules(DroidProbe::Root::NativeScanResult& result) {
        using namespace DroidProbe::Root;
        const ReadResult read_result = ReadTextFile("/proc/modules", kMaxProcFileBytes);
        if (!read_result.opened) {
            AddScanLimitation(
                result,
                "/proc/modules",
                "无法打开 /proc/modules，可能受到 procfs 权限或系统策略限制"
            );
            return;
        }
        if (!read_result.completed || read_result.truncated) {
            AddScanLimitation(
                result,
                "/proc/modules",
                "读取 /proc/modules 不完整，模块列表扫描结果可能不完整"
            );
        }

        std::istringstream input(read_result.content);
        std::string line;
        size_t evidence_count = 0;

        while (std::getline(input, line)) {
            std::istringstream line_stream(line);
            std::string module_name;
            if (!(line_stream >> module_name)) {
                continue;
            }

            for (const char* candidate : kCandidateModuleNames) {
                if (module_name == candidate) {
                    AddEvidence(
                        result,
                        kScoreKsuModule,
                        "KSU_MODULE_MATCH",
                        module_name,
                        "在 /proc/modules 中发现与 KernelSU 候选模块名完全匹配的条目；"
                        "该信号较强，但仍应结合目标 ROM 和模块来源验证"
                    );
                    ++evidence_count;
                    break;
                }
            }

            if (evidence_count >= kMaxEvidencePerSource) {
                break;
            }
        }
    } /* CheckProcModules */

    /**
     * 判断一个 procfs Socket 路径字段是否精确匹配候选 KernelSU 名称。
     *
     * <p>不使用宽泛的 substring 搜索，防止普通 Socket 名称中偶然包含关键字而误报。
     * 当前候选名称属于版本相关启发式特征，需在真实设备上验证。</p>
     */
    bool IsCandidateKsuSocket(const std::string& socket_name) {
        for (const char* candidate : kCandidateSocketNames) {
            if (socket_name == candidate) {
                return true;
            }
        }
        return false;
    } /* IsCandidateKsuSocket */

    /**
     * 读取 /proc/net/unix 并检查抽象 Unix Socket 名称。
     *
     * <p>Linux /proc/net/unix 的最后一列通常包含 Socket 路径；抽象命名空间名称
     * 常以 @ 表示。该文件是否允许普通应用读取取决于 Android 版本及安全策略。</p>
     *
     * <p>成功读取文件不是 SELinux 绕过或 KernelSU 的证据。只有实际命中候选名称
     * 才记录低至中等强度的 KernelSU 线索；候选名称本身不是 KernelSU 的稳定 ABI。</p>
     */
    void CheckAbstractSockets(DroidProbe::Root::NativeScanResult& result) {
        using namespace DroidProbe::Root;
        const ReadResult read_result = ReadTextFile("/proc/net/unix", kMaxProcFileBytes);
        if (!read_result.opened) {
            AddScanLimitation(
                result,
                "/proc/net/unix",
                "当前应用无法读取 /proc/net/unix；此类限制在 Android 上可能是正常行为，"
                "不能据此推断 KernelSU 存在或不存在"
            );
            return;
        }
        if (!read_result.completed || read_result.truncated) {
            AddScanLimitation(
                result,
                "/proc/net/unix",
                "读取 /proc/net/unix 不完整，Socket 扫描结果可能不完整"
            );
        }

        std::istringstream input(read_result.content);
        std::string line;
        size_t evidence_count = 0;

        // 第一行是字段标题；若文件为空或格式异常，则不产生阳性结论。
        if (!std::getline(input, line)) {
            AddScanLimitation(
                result,
                "/proc/net/unix",
                "/proc/net/unix 内容为空，无法完成 Socket 特征扫描"
            );
            return;
        }

        while (std::getline(input, line)) {
            std::istringstream line_stream(line);
            std::string field;
            std::string last_field;

            // 按空白拆分字段，保留最后一列作为 Socket 路径候选。
            while (line_stream >> field) {
                last_field = field;
            }

            if (last_field.empty() || !IsCandidateKsuSocket(last_field)) {
                continue;
            }

            AddEvidence(
                result,
                kScoreCandidateSocket,
                "KSU_SOCKET_CANDIDATE",
                last_field,
                "命中候选 KernelSU 抽象 Unix Socket 名称；"
                "Socket 命名并非稳定公开接口，当前只作为待实机验证的辅助线索"
            );

            ++evidence_count;
            if (evidence_count >= kMaxEvidencePerSource) {
                break;
            }
        }
    } /* CheckAbstractSockets */

    /**
     * 从 /proc/kallsyms 的符号名列提取候选 KernelSU 符号。
     *
     * <p>常见行格式为：地址、符号类型、符号名称，某些内核还会附加模块名。
     * 本实现只检查符号名是否以 ksu_ 或 kernelsu_ 开头，而不是搜索整行子串，
     * 从而减少地址、路径或其他字段造成的偶然命中。</p>
     *
     * <p>符号命中是比通用系统属性更具体的线索，但仍可能受源码版本、符号隐藏、
     * 编译方式和厂商改动影响；它不是防篡改证明。</p>
     */
    void CheckKallsyms(DroidProbe::Root::NativeScanResult& result) {
        using namespace DroidProbe::Root;
        const ReadResult read_result = ReadTextFile("/proc/kallsyms", kMaxProcFileBytes);
        if (!read_result.opened) {
            AddScanLimitation(
                result,
                "/proc/kallsyms",
                "当前应用无法读取 /proc/kallsyms；内核符号表常受权限策略限制，该限制本身不是 KernelSU 证据"
            );
            return;
        }
        if (!read_result.completed || read_result.truncated) {
            AddScanLimitation(
                result,
                "/proc/kallsyms",
                "/proc/kallsyms 读取达到上限或中途失败，符号表扫描不完整"
            );
        }

        std::istringstream input(read_result.content);
        std::string line;
        size_t evidence_count = 0;

        while (std::getline(input, line)) {
            std::istringstream line_stream(line);
            std::string address;
            std::string symbol_type;
            std::string symbol_name;

            if (!(line_stream >> address >> symbol_type >> symbol_name)) {
                continue;
            }

            const bool is_ksu_symbol =
                symbol_name.compare(0, 4, "ksu_") == 0 ||
                symbol_name.compare(0, 8, "kernelsu_") == 0;
            if (!is_ksu_symbol) {
                continue;
            }

            AddEvidence(
                result,
                kScoreKsuKernelSymbol,
                "KSU_KERNEL_SYMBOL",
                symbol_name,
                "在可读取的内核符号表中发现 KernelSU 命名特征；"
                "该符号是具体内核线索，但应结合目标内核源码或已知版本进行确认"
            );

            ++evidence_count;
            if (evidence_count >= kMaxEvidencePerSource) {
                break;
            }
        }
    } /* CheckKallsyms */

    /**
     * 获取内核版本字符串，仅作为诊断上下文。
     *
     * <p>上游 KernelSU 的兼容范围与分支、内核集成方式有关；低版本内核也可能存在
     * 手动回移植或第三方分支。因此这里不以版本号硬性跳过探测，也不把版本号本身
     * 作为 Root 阳性证据。</p>
     */
    void AddKernelVersionContext(DroidProbe::Root::NativeScanResult& result) {
        struct utsname info {};
        if (uname(&info) != 0) {
            AddScanLimitation(
                result,
                "uname",
                "uname() 获取内核版本失败，无法记录内核版本上下文"
            );
            return;
        }

        AddEvidence(
            result,
            0,
            "KERNEL_VERSION_CONTEXT",
            info.release,
            "当前内核版本仅作为 KernelSU 兼容性分析上下文；不依据版本号单独判定设备是否安装或运行 KernelSU"
        );
    } /* AddKernelVersionContext */

    /**
    * 查看 Kernel Su 的运行环境要求，发现它必须运行中 Linux 内核版本高于 4.14 的环境中
    * 这个函数就是检查当前 Linux 内核版本是否 >= 4.14
    * @return 如果当前 Linux 内核版本大于等于 4.14 返回 true，否则返回 false
    */
    bool IsKernelVersionSupportedForKsu() {
        struct utsname buf{};
        if (uname(&buf) != 0) {
            // 如果获取失败，出于防御性编程考量，默认认为可能支持，继续向下执行检测
            return true;
        }

        int major = 0;
        int minor = 0;
        // buf.release 格式通常为 "4.14.180-gabcdef" 或 "5.10.101-android12-..."
        if (sscanf(buf.release, "%d.%d", &major, &minor) == 2) {
            if (major < 4 || (major == 4 && minor < 14)) {
                // 内核版本 < 4.14，物理上不可能运行 KernelSU
                return false;
            }
        }

        return true;
    } /* IsKernelVersionSupportedForKsu */

    /**
     * @brief 探测 prctl 系统调用的异常响应，作为 KernelSU 相关的实验性辅助检测。
     *
     * @details
     * 通过调用候选 prctl option，观察系统调用的返回值和 errno。
     * 对于未知 option，常规 Linux 内核通常返回 -1 并设置 EINVAL。
     *
     * 注意：
     * 1. 异常响应不等于 KernelSU 确证，也可能来自 seccomp、
     *    厂商内核修改或其他内核扩展。
     * 2. 仅保留已知的历史 KernelSU prctl 接口候选值；
     *    其他未经源码验证的魔数不应直接用于正式检测。
     * 3. 当前上游 KernelSU 已采用基于驱动文件描述符的 ioctl UAPI，
     *    因此此探针主要覆盖历史 prctl 接口实现，不保证覆盖新版。
     * 4. 本方法只记录弱证据，不单独将设备判定为 KernelSU 已安装。
     *
     * @param result KernelSU 扫描结果，检测证据直接追加到该对象
     */
    void CheckSyscallAnomaly(DroidProbe::Root::NativeScanResult& result) {
        /**
         * 历史 KernelSU prctl 接口候选值。
         *
         * 这里仅保留历史接口中使用过的 0xDEADBEEF。
         * 其他未经目标版本源码验证的候选魔数不参与扫描，
         * 避免将其他内核扩展的接口误认为 KernelSU。
         *
         * 注意：调用前仍应针对目标版本确认该 option 配合
         * 零参数不会触发任何有副作用的操作。
         */
        struct PrctlProbe {
            int option;
            const char* name;
        };

        constexpr PrctlProbe probes[] = {
            {
                static_cast<int>(0xDEADBEEFu),
                "LEGACY_KERNEL_SU_OPTION"
            }
        };

        for (const PrctlProbe& probe : probes) {
            // 每次调用前清空 errno，避免使用上一次系统调用遗留的错误码。
            errno = 0;

            // 使用零参数进行实验性探测。
            // 此处不执行提权命令，不传入任何有效用户空间指针。
            const int ret = prctl(
                probe.option,
                0,
                0,
                0,
                0
            );

            // 立即保存 errno，避免后续函数调用覆盖它。
            const int error = errno;

            // 情况一：返回 EINVAL。
            // 这是未知 prctl option 的常规响应。
            // 但不能据此排除 KernelSU，因为目标版本可能不采用此接口，
            // 也可能对非授权调用者隐藏接口行为。
            if (ret == -1 && error == EINVAL) {
                continue;
            }

            // 记录此次探测的原始响应，便于后续实机验证。
            const std::string value =
                std::string("option=") + probe.name
                    + ",ret=" + std::to_string(ret)
                    + ",errno=" + std::to_string(error);

            // 情况二：系统调用成功。
            // 这说明候选 option 得到了处理，但无法唯一归因于 KernelSU。
            // 因此只作为低置信度辅助证据，不赋予确诊级分值。
            if (ret >= 0) {
                AddEvidence(
                    result,
                    20,
                    "PRCTL_OPTION_HANDLED",
                    value,
                    "候选 prctl option 返回成功，可能存在内核扩展处理逻辑；"
                    "该行为并非 KernelSU 独有，需结合其他证据验证"
                );

                // 当前仅有一个经过筛选的候选值，命中后结束探测。
                return;
            }

            // 情况三：调用受到权限限制，或系统不支持该探测路径。
            // EPERM、EACCES、ENOSYS 等错误都不能单独证明 KernelSU。
            if (error == EPERM || error == EACCES || error == ENOSYS) {
                AddEvidence(
                    result,
                    0,
                    "PRCTL_PROBE_INCONCLUSIVE",
                    value,
                    "候选 prctl 探测受到权限限制或接口不可用，"
                    "无法据此判断是否存在 KernelSU"
                );
                continue;
            }

            // 情况四：其他非预期响应。
            // 可能由内核版本差异、安全策略或其他内核扩展造成。
            // 保留原始响应供调试，但不直接增加 KernelSU 风险分。
            AddEvidence(
                result,
                0,
                "PRCTL_UNEXPECTED_RESPONSE",
                value,
                "prctl 返回非预期错误，属于待验证的系统调用行为异常，"
                "不能单独作为 KernelSU 检出证据"
            );
        }
    } /* CheckSyscallAnomaly */
} // namespace


/**
 * 执行一次完整的 KernelSU 特征扫描。
 *
 * @return 含最高命中分值、扫描状态及证据列表的结果对象
 */
DroidProbe::Root::NativeScanResult DroidProbe::Root::KernelSuScanner::Scan() {
    // Linux 内核版本不支持 KernelSU
    if (!IsKernelVersionSupportedForKsu()) {
        return {};
    }

    NativeScanResult result;

    try {
        AddKernelVersionContext(result);
        CheckProcModules(result);
        CheckAbstractSockets(result);
        CheckKsuPaths(result);
        CheckKallsyms(result);
        CheckSyscallAnomaly(result);
    }
    catch (...) {
        result.state = NativeScanState::ERROR;
        AddEvidence(
            result,
            0,
            "NATIVE_SCAN_EXCEPTION",
            "KernelSuScanner::Scan",
            "Native 扫描过程中发生未预期异常，扫描结果可能不完整"
        );
    }

    return result;
} /* KernelSuScanner::Scan */
