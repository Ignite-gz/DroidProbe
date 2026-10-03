//
// Created by ignite on 9/30/26.
//

#include "apatch_scanner.h"
#include <string>
#include <sstream>
#include <fstream>
#include <dirent.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include "droid_probe_log.h"

namespace {

    // APatch 官方当前声明只支持 ARM64。
    // 注意：这里用于“检测范围说明”，不是用 uname.machine 简单判断设备是否为 64 位 Android。
    constexpr const char* kExpectedMachine = "aarch64";

    // APatch 官方当前 README / 文档声明的 Linux kernel 支持范围是 3.18 - 6.12。
    constexpr int kMinimumKernelMajor = 3;
    constexpr int kMinimumKernelMinor = 18;
    constexpr int kMaximumKernelMajor = 6;
    constexpr int kMaximumKernelMinor = 12;

    // Native 读取普通文本文件时限制最大大小，避免异常文件导致无限制内存增长。
    constexpr size_t kMaxSmallFileBytes = 256 * 1024;

    // /proc/kallsyms 在正常设备上可能很大，所以采用逐行读取，不一次性加载整个文件。
    constexpr size_t kMaxKallsymsLineBytes = 1024;

    // 单次进程扫描最多读取的 PID 数，避免在异常环境中无限遍历 /proc。
    constexpr size_t kMaxProcessEntries = 8192;

    // 单次扫描最多记录同类证据，避免恶意环境制造数千条相同证据导致上层内存增长。
    constexpr size_t kMaxRepeatedEvidence = 16;

    /**
     * 当前 APatch 的稳定配置路径。
     *
     * APatch 官方 release notes 和生态项目都持续使用 /data/adb/ap/package_config；
     * 它比“su/kp 文件名”稳定得多，但仍然不是不可伪造的绝对指纹。
     */
    constexpr const char* kPackageConfigPath = "/data/adb/ap/package_config";

    /** APatch 用户空间工作目录。 */
    constexpr const char* kAPatchDirectory = "/data/adb/ap";

    /** APatch daemon 的已知工作目录线索。 */
    constexpr const char* kAPatchDaemonDirectory = "/data/adb/apd";

    /**
     * 旧版本 / 当前部分构建可能留下的可选 APatch 开关文件。
     * 这些文件不是 APatch 必然存在的文件，因此只做低权重证据。
     */
    constexpr const char* kOverlayEnablePath = "/data/adb/.overlay_enable";
    constexpr const char* kLiteModeEnablePath = "/data/adb/.litemode_enable";

    /**
     * KernelPatch 当前 SuperCall 实现中具有代表性的全局符号 / 函数名。
     *
     * 这些名字来自公开的 KernelPatch 源码，例如 supercall_install、kpver、
     * load_ap_package_config 等。它们并不等价于“官方 APatch 专属”：
     * 单独安装 KernelPatch 也可能出现这些符号，因此这里的 evidence 类型明确使用
     * KERNELPATCH_*，最终需要结合 APatch 用户空间证据才能提高 APatch 置信度。
     */
    constexpr const char* kKernelPatchSymbols[] = {
        "supercall_install",
        "is_trusted_manager_uid",
        "kp_control_feature_sc",
        "load_ap_package_config",
        "kpver"
    };

    /**
     * APatch / KernelPatch 用户空间 daemon 的已知名称。
     *
     * 名称可以改，因此这里只作为辅助证据。
     */
    constexpr const char* kPotentialDaemonNames[] = {
        "apd",
        "apatchd"
    };

    /**
     * 不同版本 / 衍生实现可能使用的抽象 Unix socket 名称候选。
     * 这些名称必须被视为“辅助指纹”，不能作为所有 APatch 版本的硬编码事实。
     */
    constexpr const char* kPotentialSocketNames[] = {
        "@apd",
        "@apatch"
    };

    bool IsPotentialAPatchProcessName(const std::string& name) {
        // APatch 当前 daemon 的常见名字。
        if (name == "apd" || name == "apatchd") {
            return true;
        }

        // 线程名在部分实现中可能带 APatch 前缀；只作为辅助观察。
        return name.find("apd") != std::string::npos;
    } /* IsPotentialAPatchProcessName */

    /**
     * 从 /proc/kallsyms 行中提取最后一个字段（symbol name）。
     * 一个典型行类似：
     *
     * ffffffc000123456 T supercall_install
     */
    std::string ExtractKallsymsName(const std::string& line) {
        std::istringstream stream(line);
        std::string address;
        std::string type;
        std::string name;

        if (!(stream >> address >> type >> name)) {
            return {};
        }

        return name;
    } /* ExtractKallsymsName */

    /**
      * 判断一个路径是否像 APatch 当前 / 历史结构中的路径。
      * 这个函数只用于字符串分类，不产生任何安全结论。
      */
    bool ContainsAPatchPathHint(const std::string& value) {
        return value.find("/data/adb/ap/") != std::string::npos
            || value.find("/data/adb/apd/") != std::string::npos
            || value.find("/data/adb/ap/package_config") != std::string::npos;
    } /* ContainsAPatchPathHint */

    /**
    * @brief 检查当前 Linux 内核版本和 CPU 架构是否支持 APatch
    * @param result 用于向 native 扫描汇总结果中添加
    * @return
    */
    bool AddKernelVersionContext(DroidProbe::Root::NativeScanResult& result) {
        // utsname 是最老牌且跨 Android 版本可用的 Linux 内核信息接口。
        struct utsname info{};

        // uname 失败时，不能假设内核版本，更不能因为无法读取版本而直接判定“没有 APatch”。
        if (uname(&info) != 0) {
            DroidProbe::Log::error(__FUNCTION__, "%s", "无法通过 uname 获取当前 Linux 内核版本，后续探针继续执行");
            AddEvidence(
                result,
                0,
                "KERNEL_VERSION_UNAVAILABLE",
                "uname",
                "无法通过 uname 获取当前 Linux 内核版本，后续探针继续执行"
            );
            return false;
        }

        // 解析 major/minor，忽略 Android vendor 后缀。
        int major = -1;
        int minor = -1;
        if (!DroidProbe::Root::ParseKernelRelease(info.release, major, minor)) {
            AddEvidence(
                result,
                0,
                "KERNEL_VERSION_PARSE_FAILED",
                info.release,
                "uname 返回的 kernel release 无法解析为 major.minor"
            );
            return false;
        }

        // 保存当前 Android 设备架构信息作为上下文证据，但不单独评分。
        if (std::strcmp(info.machine, kExpectedMachine) != 0) {
            // APatch 不支持 ARM64 以外的设备
            return false;
        }

        // 检查是否低于官方声明的最低内核版本或者高于官方声明的最高内核版本。
        const bool below_minimum =
            DroidProbe::Root::CompareKernelVersion(major, minor, kMinimumKernelMajor, kMinimumKernelMinor) < 0;
        const bool above_maximum =
            DroidProbe::Root::CompareKernelVersion(major, minor, kMaximumKernelMajor, kMaximumKernelMinor) > 0;

        if (below_minimum || above_maximum) {
            return false;
        }

        // 到这里说明内核版本落在官方声明的范围内，或者属于未来版本。
        return true;
    } /* AddKernelVersionContext */

    void CheckAPatchArtifacts(DroidProbe::Root::NativeScanResult& result) {
        using namespace DroidProbe::Root;

        // 要检查的目标路径都来自 APatch 用户空间布局，而不是泛化的 /data/adb。
        constexpr const char* paths[] = {
            kAPatchDirectory,
            kPackageConfigPath,
            kAPatchDaemonDirectory,
            kOverlayEnablePath,
            kLiteModeEnablePath
        };

        // 分别检查每条路径，避免一次错误导致整个探针结束。
        for (const char* path : paths) {
            // access(F_OK) 只检查 inode 是否可见，不要求当前进程拥有读写权限。
            const int state = CheckPathExists(path);

            if (state == PathAccessResult::PathExists) {
                // /data/adb/ap/package_config 是目前最有价值的 APatch 用户空间特征。
                if (std::strcmp(path, kPackageConfigPath) == 0) {
                    AddEvidence(
                        result,
                        70,
                        "APATCH_PACKAGE_CONFIG",
                        path,
                        "发现 APatch SuperUser 配置文件 package_config；"
                        "该文件是 APatch 当前用户空间实现中的高价值特征"
                    );
                    continue;
                }

                // /data/adb/ap 目录比 package_config 弱，因为其他组件可能复用 /data/adb 下的结构。
                if (std::strcmp(path, kAPatchDirectory) == 0) {
                    AddEvidence(
                        result,
                        55,
                        "APATCH_WORK_DIRECTORY",
                        path,
                        "发现 APatch 用户空间工作目录 /data/adb/ap；"
                        "这是较强的 APatch 用户空间痕迹，但不能单独证明内核已加载"
                    );
                    continue;
                }

                // /data/adb/apd 可以支持识别用户空间 daemon 的安装结构。
                if (std::strcmp(path, kAPatchDaemonDirectory) == 0) {
                    AddEvidence(
                        result,
                        50,
                        "APATCH_DAEMON_DIRECTORY",
                        path,
                        "发现 APatch daemon 相关工作目录 /data/adb/apd；"
                        "该证据需要结合其他 APatch 特征进行归因"
                    );
                    continue;
                }

                // /data/adb/.overlay_enable 和 /data/adb/.litemode_enable
                // 这两个开关文件是特定版本 / 模式下才会存在的，可作为低权重辅助证据。
                AddEvidence(
                    result,
                    25,
                    "APATCH_OPTION_FILE",
                    path,
                    "发现 APatch 可选配置开关文件；该文件不是 APatch 的必要组件"
                );

                continue;
            }

            if (state == PathAccessResult::PathNotFound) {
                // ENOENT 只表示目标不存在，绝不能理解成“SELinux 被绕过”。
                // 例如全新、没有 APatch 的设备本来就应该得到 ENOENT。
                AddEvidence(
                    result,
                    0,
                    "APATCH_PATH_NOT_FOUND",
                    path,
                    "目标路径不存在；该结果不能用于证明 APatch 不存在，也不能证明安全策略被绕过"
                );
                continue;
            }

            // -1 表示访问结果不可确定，例如 EACCES、EPERM、I/O 错误等。
            // 这种情况应该保留可观测性信息，而不是转换成 NOT_DETECTED。
            AddEvidence(
                result,
                0,
                "APATCH_PATH_INACCESSIBLE",
                path,
                "无法判断目标路径是否存在，可能受到 DAC、SELinux 或文件系统权限限制"
            );
        }
    }

    void CheckUserSpaceProcesses(DroidProbe::Root::NativeScanResult& result) {
        // 打开 /proc 目录，读取当前应用能够观察到的进程目录。
        DIR* proc = opendir("/proc");

        if (proc == nullptr) {
            // 无法读取 /proc 时，不把它解释为“没有 APatch”。
            AddEvidence(
                result,
                0,
                "PROC_UNOBSERVABLE",
                "/proc",
                "无法读取 /proc 进程目录，无法进行 APatch daemon 进程检测"
            );
            return;
        }

        size_t scanned = 0;
        size_t reported = 0;

        // 逐个遍历 /proc 下的 PID 目录。
        while (dirent* entry = readdir(proc)) {
            // 将目录名限制为纯数字，避免读取 self、net 等非进程目录。
            if (!DroidProbe::Root::IsNumeric(entry->d_name)) {
                continue;
            }

            // 限制扫描数量，防止异常环境拥有巨量 PID 时消耗过多时间
            if (++scanned > kMaxProcessEntries) {
                AddEvidence(
                    result,
                    0,
                    "PROC_SCAN_TRUNCATED",
                    "/proc",
                    "进程数量超过扫描上限，本次进程检测被截断"
                );
                break;
            }

            // 将 PID 字符串转换成整数
            const int pid = std::atoi(entry->d_name);

            // 读取 /proc/<pid>/comm 中的进程名字
            std::string process_name;
            if (!DroidProbe::Root::ReadProcessName(pid, process_name)) {
                continue;
            }

            // 如果名字看起来与 APatch daemon 没有关系，直接跳过
            if (!IsPotentialAPatchProcessName(process_name)) {
                continue;
            }

            // 进一步读取实际可执行文件路径，尽量避免只凭 comm 名称做判断。
            char exe_path[4096]{};
            std::string executable_path;
            const std::string proc_exe = std::string("/proc/") + std::to_string(pid) + "/exe";
            const ssize_t length = readlink(proc_exe.c_str(), exe_path, sizeof(exe_path) - 1);

            if (length > 0) {
                exe_path[length] = '\0';
                executable_path = exe_path;
            }

            // 只要看到 apd 进程，就给中等辅助证据；路径和进程名都命中时再提高置信度。
            int score = 35;
            std::string detail =
                "发现疑似 APatch daemon 进程；进程名和路径均可能被修改，因此该证据不能单独作为 APatch 确诊";

            if (executable_path.find("/data/adb/apd/") != std::string::npos) {
                score = 55;
                detail =
                    "发现疑似 APatch daemon，且其可执行文件路径位于 /data/adb/apd；这是比单独进程名更强的用户空间证据";
            }

            AddEvidence(
                result,
                score,
                "APATCH_DAEMON_PROCESS",
                std::string("pid=") + std::to_string(pid)
                    + ",name=" + process_name
                    + (executable_path.empty() ? "" : ",exe=" + executable_path),
                detail.c_str()
            );

            // 避免同一个 daemon 的不同线程或 clone 实例产生过多重复证据。
            if (++reported >= kMaxRepeatedEvidence) {
                break;
            }
        } /* while */

        // 关闭 /proc 目录句柄。
        closedir(proc);
    } /* CheckUserSpaceProcesses */

    void CheckKernelSymbols(DroidProbe::Root::NativeScanResult& result) {
        // /proc/kallsyms 是当前 APatch 官方安装要求中非常重要的内核能力之一，
        // 但“能够打开它”本身不是 APatch 指纹。
        std::ifstream file("/proc/kallsyms");

        if (!file.is_open()) {
            // 在正常 Android 用户应用上下文中无法访问 kallsyms 是常见情况。
            // 这里只记为不可观测，不计风险分。
            AddEvidence(
                result,
                0,
                "KALLSYMS_UNOBSERVABLE",
                "/proc/kallsyms",
                "无法读取内核符号表；这属于常见 Android 权限限制，不能据此否定 APatch"
            );
            return;
        }

        AddEvidence(
            result,
            0,
            "KALLSYMS_READABLE",
            "/proc/kallsyms",
            "当前应用能够读取 /proc/kallsyms；该事实本身不是 APatch 专属证据"
        );

        // 使用布尔数组记录已经命中的 KernelPatch 符号，避免同一符号在大量引用中重复计分。
        bool matched[sizeof(kKernelPatchSymbols) / sizeof(kKernelPatchSymbols[0])]{};

        // 逐行读取 kallsyms，避免把整个符号表加载到内存。
        std::string line;
        while (std::getline(file, line)) {
            // 超过限制的异常长行直接跳过，防止恶意 procfs 内容导致大量内存操作。
            if (line.size() > kMaxKallsymsLineBytes) {
                continue;
            }

            // 从标准 kallsyms 格式中提取符号名称。
            const std::string symbol = ExtractKallsymsName(line);
            if (symbol.empty()) {
                continue;
            }

            // 检查当前符号是否属于已知 KernelPatch 特征集合。
            for (size_t i = 0; i < sizeof(kKernelPatchSymbols) / sizeof(kKernelPatchSymbols[0]); ++i) {
                if (matched[i]) {
                    continue;
                }

                if (symbol == kKernelPatchSymbols[i]) {
                    matched[i] = true;

                    // 单个 KernelPatch 符号是较强证据，但因为 KernelPatch 可以单独安装，
                    // 这里不直接称为“APatch 确诊”。
                    AddEvidence(
                        result,
                        65,
                        "KERNELPATCH_SYMBOL",
                        symbol,
                        "在 /proc/kallsyms 中发现经过 KernelPatch 源码验证的符号；"
                        "该证据可以确认 KernelPatch 相关内核能力，但单独不足以区分完整 APatch"
                    );
                }
            }
        } /* while */
    } /* CheckKernelSymbols */

    void CheckUnixSockets(DroidProbe::Root::NativeScanResult& result) {
        // 读取 /proc/net/unix 可观察当前 network namespace 中的 Unix socket 表。
        std::ifstream file("/proc/net/unix");

        if (!file.is_open()) {
            // Android 对普通应用读取该文件通常有限制，因此打不开并不异常。
            AddEvidence(
                result,
                0,
                "UNIX_SOCKET_TABLE_UNOBSERVABLE",
                "/proc/net/unix",
                "无法读取 Unix socket 表，不能通过 socket 特征判断 APatch"
            );
            return;
        }

        // 丢弃 /proc/net/unix 的表头。
        std::string line;
        std::getline(file, line);

        size_t reported = 0;

        // 遍历 socket 表中的每个 socket。
        while (std::getline(file, line)) {
            // 超过限制的异常长行直接跳过，防止恶意 procfs 内容导致大量内存操作。
            if (line.size() > kMaxKallsymsLineBytes) {
                continue;
            }

            // 只在 socket 名称本身包含已知候选名字时记录证据。
            bool matched = false;
            std::string matched_name;

            for (const char* candidate : kPotentialSocketNames) {
                if (line.find(candidate) != std::string::npos) {
                    matched = true;
                    matched_name = candidate;
                    break;
                }
            }

            if (!matched) {
                continue;
            }

            // 这些名字不是所有 APatch 版本保证存在的永久 API，因此使用辅助分值。
            AddEvidence(
                result,
                60,
                "APATCH_UNIX_SOCKET",
                matched_name,
                "在 /proc/net/unix 中发现疑似 APatch daemon 的抽象 Unix socket；"
                "该名称属于版本相关辅助特征，需要结合其他证据确认"
            );

            // 避免同一个 daemon 的不同线程或 clone 实例产生过多重复证据。
            if (++reported >= kMaxRepeatedEvidence) {
                break;
            }
        }
    } /* CheckUnixSockets */

    void CheckMountInfo(DroidProbe::Root::NativeScanResult& result) {
        // /proc/self/mountinfo 比 mount 命令更适合应用内读取，因为它对应当前进程所在的 mount namespace。
        std::ifstream file("/proc/self/mountinfo");

        if (!file.is_open()) {
            // 无法读取 mountinfo 时直接结束此探针，不将其解释成“没有 APatch”。
            AddEvidence(
                result,
                0,
                "MOUNTINFO_UNOBSERVABLE",
                "/proc/self/mountinfo",
                "无法读取当前进程挂载信息，不能通过挂载特征判断 APatch"
            );
            return;
        }

        size_t reported = 0;
        std::string line;

        // 逐行解析 mountinfo；这里不强制要求某个固定 mount source，因为 APatch 的挂载模式会变化。
        while (std::getline(file, line)) {
            if (line.size() > kMaxKallsymsLineBytes) {
                continue;
            }

            // 只要挂载行同时包含 APatch 已知工作目录，就记录辅助证据。
            if (!ContainsAPatchPathHint(line)) {
                continue;
            }

            AddEvidence(
                result,
                35,
                "APATCH_MOUNT_HINT",
                line,
                "当前进程挂载命名空间中发现 APatch 相关路径；"
                "挂载实现会随 APatch 版本变化，因此只作为辅助证据"
            );

            // 避免同一个 daemon 的不同线程或 clone 实例产生过多重复证据。
            if (++reported >= kMaxRepeatedEvidence) {
                break;
            }
        }
    } /* CheckMountInfo */
} // namespace


DroidProbe::Root::NativeScanResult DroidProbe::Root::APatchScanner::Scan() {
    NativeScanResult result;
    try {
        // 第一步：记录并检查 kernel version。
        // 如果版本超出已验证范围，那么就不再进行检查
        const bool kernel_version_valid = AddKernelVersionContext(result);

        // 低于 3.18 的 kernel 在官方 APatch 支持范围之外。
        if (!kernel_version_valid) {
            return result;
        }

        // 第二步：扫描 APatch 稳定用户空间结构。
        CheckAPatchArtifacts(result);

        // 第三步：扫描可观察进程，寻找 apd / apatchd 等用户空间组件。
        CheckUserSpaceProcesses(result);

        // 第四步：扫描 kernel symbols，寻找源码验证的 KernelPatch 特征。
        CheckKernelSymbols(result);

        // 第五步：扫描 Unix sockets，寻找版本相关的 APatch daemon IPC 特征。
        CheckUnixSockets(result);

        // 第六步：扫描当前进程 mount namespace 中的 APatch 路径痕迹。
        CheckMountInfo(result);
    }
    catch (...) {
        // Native 层绝不能让 C++ 异常穿过 JNI 边界。
        // 发生异常时保留已经收集的证据，同时明确告诉上层“结果不完整”。
        result.state = NativeScanState::ERROR;
        AddEvidence(
            result,
            0,
            "NATIVE_SCAN_EXCEPTION",
            "APatchScanner::Scan",
            "Native APatch 扫描过程中发生未预期异常，扫描结果可能不完整"
        );
    }

    return result;
} /* APatchScanner::Scan */
