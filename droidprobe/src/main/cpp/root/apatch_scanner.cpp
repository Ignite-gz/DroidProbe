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

namespace DroidProbe {
    namespace Root {

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
             * 路径访问结果。
             *
             * 0 = 不存在；
             * 1 = 存在；
             * -1 = 无法判断（例如权限拒绝、I/O 错误等）。
             */
            constexpr int kPathNotAccessible = -1;
            constexpr int kPathNotFound = 0;
            constexpr int kPathExists = 1;

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

            /**
             * 将 kernel version (major, minor) 映射成一个可比较的二元版本关系。
             */
            int CompareKernelVersion(
                int major,
                int minor,
                int other_major,
                int other_minor) {
                if (major != other_major) {
                    return major < other_major ? -1 : 1;
                }

                if (minor != other_minor) {
                    return minor < other_minor ? -1 : 1;
                }

                return 0;
            }

            /**
             * 从类似 5.10.177-android... 的字符串中解析 major/minor。
             */
            bool ParseKernelRelease(
                const char* release,
                int& major,
                int& minor) {
                if (release == nullptr) {
                    return false;
                }

                major = -1;
                minor = -1;

                // sscanf 只关心最开始的 major.minor，不关心后面的 ABI / vendor 后缀。
                if (std::sscanf(release, "%d.%d", &major, &minor) != 2) {
                    return false;
                }

                // 拒绝异常负版本，避免后续比较产生无意义结果。
                return major >= 0 && minor >= 0;
            }

            /**
             * 删除 /proc/kallsyms 一行末尾的换行符以及多余空白。
             */
            std::string Trim(const std::string& value) {
                size_t begin = 0;
                size_t end = value.size();

                while (begin < end && std::isspace(static_cast<unsigned char>(value[begin]))) {
                    ++begin;
                }

                while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
                    --end;
                }

                return value.substr(begin, end - begin);
            }

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
            }

            /**
             * 判断一个路径是否像 APatch 当前 / 历史结构中的路径。
             * 这个函数只用于字符串分类，不产生任何安全结论。
             */
            bool ContainsAPatchPathHint(const std::string& value) {
                return value.find("/data/adb/ap/") != std::string::npos
                    || value.find("/data/adb/apd/") != std::string::npos
                    || value.find("/data/adb/ap/package_config") != std::string::npos;
            }

        } // namespace

        void APatchScanner::AddEvidence(
            APatchScanResult& result,
            int score,
            const char* rule,
            const std::string& target,
            const std::string& detail) {
            // 确保 rule 不为空，避免最终 Java DetectionEvidence 出现无意义字段。
            if (rule == nullptr) {
                return;
            }

            // 记录证据对象；所有字符串都复制到 C++ result 中，JNI 层稍后统一转换。
            APatchEvidence evidence;
            evidence.score = std::max(score, 0);
            evidence.rule = rule;
            evidence.target = target;
            evidence.detail = detail;

            // 将证据加入统一列表。
            result.evidences.push_back(std::move(evidence));

            // 采用“最高有效证据分值”而不是简单累加，避免相关信号重复计分。
            result.max_score = std::max(result.max_score, std::max(score, 0));

            // 只要出现 APatch / KernelPatch 阳性证据，暂时将状态标为 DETECTED；
            // 对最终 APatch 归因仍然由 Java 层结合多条证据进行解释。
            if (score > 0 && result.state != APatchScanState::ERROR) {
                result.state = APatchScanState::DETECTED;
            }
        }

        bool APatchScanner::AddKernelVersionContext(APatchScanResult& result) {
            // utsname 是最老牌且跨 Android 版本可用的 Linux 内核信息接口。
            struct utsname info{};

            // uname 失败时，不能假设内核版本，更不能因为无法读取版本而直接判定“没有 APatch”。
            if (uname(&info) != 0) {
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
            if (!ParseKernelRelease(info.release, major, minor)) {
                AddEvidence(
                    result,
                    0,
                    "KERNEL_VERSION_PARSE_FAILED",
                    info.release,
                    "uname 返回的 kernel release 无法解析为 major.minor"
                );
                return false;
            }

            // 保存内核版本，供后续 JNI / Java 层调试展示和结果解释使用。
            result.kernel_major = major;
            result.kernel_minor = minor;

            // 保存当前 Android 设备架构信息作为上下文证据，但不单独评分。
            if (std::strcmp(info.machine, kExpectedMachine) != 0) {
                AddEvidence(
                    result,
                    0,
                    "APATCH_ARCHITECTURE_UNEXPECTED",
                    info.machine,
                    "APatch 当前官方支持 ARM64；当前设备 machine 字段不是 aarch64，"
                    "因此正式 APatch 检测置信度应降低"
                );
            }

            // 检查是否低于官方声明的最低内核版本。
            const bool below_minimum =
                CompareKernelVersion(
                    major,
                    minor,
                    kMinimumKernelMajor,
                    kMinimumKernelMinor) < 0;

            if (below_minimum) {
                // 官方当前文档声明 APatch 支持从 Linux 3.18 开始，因此低于 3.18 时，
                // 正式 APatch 检测没有必要继续把阳性特征当作可信结果。
                AddEvidence(
                    result,
                    0,
                    "KERNEL_VERSION_OUT_OF_RANGE",
                    info.release,
                    "Linux 内核版本低于 APatch 当前官方声明的最低版本 3.18"
                );

                result.state = APatchScanState::UNSUPPORTED;
                return false;
            }

            // 检查是否高于目前官方声明的最高版本 6.12。
            const bool above_maximum =
                CompareKernelVersion(
                    major,
                    minor,
                    kMaximumKernelMajor,
                    kMaximumKernelMinor) > 0;

            if (above_maximum) {
                // 未来内核不应被强行判定为“不支持 APatch”，因为项目以后可能扩展支持。
                // 这里把它标记为 UNKNOWN，但仍然继续运行用户空间探针，以提高前向兼容能力。
                AddEvidence(
                    result,
                    0,
                    "KERNEL_VERSION_BEYOND_VERIFIED_RANGE",
                    info.release,
                    "当前内核高于 APatch 当前公开声明的最高验证范围 6.12；"
                    "仍执行通用探针，但检测结果只能视为未知/实验性"
                );

                result.state = APatchScanState::UNKNOWN;
            }

            // 到这里说明内核版本落在官方声明的范围内，或者属于未来版本。
            return true;
        }

        void APatchScanner::CheckAPatchArtifacts(APatchScanResult& result) {
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

                if (state == kPathExists) {
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

                if (state == kPathNotFound) {
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

                result.filesystem_observable = false;
            }

            // 如果至少有一个关键 APatch 路径能够被正常观察，就将文件系统标记为可观察。
            // 这里的“可观察”只是扫描质量信息，不是阳性证据。
            if (CheckPathExists(kAPatchDirectory) != kPathNotAccessible
                || CheckPathExists(kPackageConfigPath) != kPathNotAccessible) {
                result.filesystem_observable = true;
            }
        }

        void APatchScanner::CheckUserSpaceProcesses(APatchScanResult& result) {
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

            // 标记 /proc 至少可以读取目录。
            result.proc_observable = true;

            size_t scanned = 0;
            size_t reported = 0;

            // 逐个遍历 /proc 下的 PID 目录。
            while (dirent* entry = readdir(proc)) {
                // 将目录名限制为纯数字，避免读取 self、net 等非进程目录。
                if (!IsNumeric(entry->d_name)) {
                    continue;
                }

                // 限制扫描数量，防止异常环境拥有巨量 PID 时消耗过多时间。
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

                // 将 PID 字符串转换成整数。
                const int pid = std::atoi(entry->d_name);

                // 读取 /proc/<pid>/comm 中的进程名字。
                std::string process_name;
                if (!ReadProcessName(pid, process_name)) {
                    continue;
                }

                // 如果名字看起来与 APatch daemon 没有关系，直接跳过。
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
                    "发现疑似 APatch daemon 进程；进程名和路径均可能被修改，"
                    "因此该证据不能单独作为 APatch 确诊";

                if (executable_path.find("/data/adb/apd/") != std::string::npos) {
                    score = 55;
                    detail =
                        "发现疑似 APatch daemon，且其可执行文件路径位于 /data/adb/apd；"
                        "这是比单独进程名更强的用户空间证据";
                }

                AddEvidence(
                    result,
                    score,
                    "APATCH_DAEMON_PROCESS",
                    std::string("pid=") + std::to_string(pid)
                        + ",name=" + process_name
                        + (executable_path.empty() ? "" : ",exe=" + executable_path),
                    detail
                );

                // 避免同一个 daemon 的不同线程或 clone 实例产生过多重复证据。
                if (++reported >= kMaxRepeatedEvidence) {
                    break;
                }
            }

            // 关闭 /proc 目录句柄。
            closedir(proc);
        }

        void APatchScanner::CheckKernelSymbols(APatchScanResult& result) {
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

            // 文件能够打开说明当前应用具有比典型 untrusted_app 更强的内核符号可见性；
            // 但这是环境异常线索，不应直接当成 APatch。
            result.proc_observable = true;

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
                for (size_t i = 0;
                    i < sizeof(kKernelPatchSymbols) / sizeof(kKernelPatchSymbols[0]);
                    ++i) {

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
            }
        }

        void APatchScanner::CheckUnixSockets(APatchScanResult& result) {
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

            // 文件能够打开，只表示当前应用的 proc 可见性较强，不计 APatch 分值。
            result.proc_observable = true;

            // 丢弃 /proc/net/unix 的表头。
            std::string line;
            std::getline(file, line);

            size_t reported = 0;

            // 遍历 socket 表中的每个 socket。
            while (std::getline(file, line)) {
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

                if (++reported >= kMaxRepeatedEvidence) {
                    break;
                }
            }
        }

        void APatchScanner::CheckMountInfo(APatchScanResult& result) {
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

            // 当前进程至少拥有基础 mount namespace 可见性。
            result.filesystem_observable = true;

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

                if (++reported >= kMaxRepeatedEvidence) {
                    break;
                }
            }
        }

        bool APatchScanner::ReadTextFile(
            const char* path,
            std::string& out,
            size_t max_bytes) {
            // 参数检查避免异常调用直接崩溃。
            if (path == nullptr || max_bytes == 0) {
                return false;
            }

            // 以只读方式打开，避免检测器产生任何文件系统副作用。
            const int fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                return false;
            }

            // 清空输出缓冲。
            out.clear();
            out.reserve(std::min(max_bytes, static_cast<size_t>(4096)));

            // 使用固定小缓冲读取文件。
            char buffer[4096];

            while (out.size() < max_bytes) {
                // 每次读取不超过剩余容量。
                const size_t remaining = max_bytes - out.size();
                const size_t requested = std::min(remaining, sizeof(buffer));

                // 读取文件内容。
                const ssize_t length = read(fd, buffer, requested);

                // EOF。
                if (length == 0) {
                    break;
                }

                // 读取错误。
                if (length < 0) {
                    close(fd);
                    out.clear();
                    return false;
                }

                // 将本轮数据追加到结果字符串。
                out.append(buffer, static_cast<size_t>(length));
            }

            // 关闭文件描述符。
            close(fd);

            return true;
        }

        int APatchScanner::CheckPathExists(const char* path) {
            // 无路径参数时无法判断。
            if (path == nullptr) {
                return kPathNotAccessible;
            }

            // access(F_OK) 只检查路径是否存在，不尝试读取、写入或执行文件。
            if (access(path, F_OK) == 0) {
                return kPathExists;
            }

            // ENOENT 或 ENOTDIR 表示目标路径确实不存在。
            if (errno == ENOENT || errno == ENOTDIR) {
                return kPathNotFound;
            }

            // 其他错误统一归类为不可确定，例如 EACCES / EPERM / EIO。
            return kPathNotAccessible;
        }

        bool APatchScanner::IsNumeric(const char* text) {
            // 空字符串不是合法 PID。
            if (text == nullptr || *text == '\0') {
                return false;
            }

            // PID 目录名必须由数字组成。
            for (const char* current = text; *current != '\0'; ++current) {
                if (!std::isdigit(static_cast<unsigned char>(*current))) {
                    return false;
                }
            }

            return true;
        }

        bool APatchScanner::IsPotentialAPatchProcessName(const std::string& name) {
            // APatch 当前 daemon 的常见名字。
            if (name == "apd" || name == "apatchd") {
                return true;
            }

            // 线程名在部分实现中可能带 APatch 前缀；只作为辅助观察。
            return name.find("apd") != std::string::npos;
        }

        bool APatchScanner::ReadProcStatusField(
            int pid,
            const char* field,
            std::string& value) {
            // 参数检查。
            if (pid <= 0 || field == nullptr) {
                return false;
            }

            // 拼接 /proc/<pid>/status 路径。
            const std::string path =
                std::string("/proc/") + std::to_string(pid) + "/status";

            // 读取完整的小型 status 文件。
            std::string content;
            if (!ReadTextFile(path.c_str(), content, 16384)) {
                return false;
            }

            // 构造需要查找的字段前缀，例如 Name: 或 Uid:。
            const std::string prefix = std::string(field) + ":";

            // 按行扫描。
            size_t begin = 0;
            while (begin < content.size()) {
                const size_t end = content.find('\n', begin);
                const size_t length = (end == std::string::npos)
                    ? content.size() - begin
                    : end - begin;

                const std::string line = content.substr(begin, length);

                if (line.compare(0, prefix.size(), prefix) == 0) {
                    value = Trim(line.substr(prefix.size()));
                    return true;
                }

                if (end == std::string::npos) {
                    break;
                }

                begin = end + 1;
            }

            return false;
        }

        bool APatchScanner::ReadProcessName(int pid, std::string& name) {
            // 优先读取 /proc/<pid>/comm，因为它只有极小的固定长度。
            const std::string path =
                std::string("/proc/") + std::to_string(pid) + "/comm";

            if (ReadTextFile(path.c_str(), name, 256)) {
                name = Trim(name);
                return !name.empty();
            }

            // comm 无法读取时，再尝试读取 cmdline 的 argv[0]。
            const std::string cmdline_path =
                std::string("/proc/") + std::to_string(pid) + "/cmdline";

            if (!ReadTextFile(cmdline_path.c_str(), name, 1024)) {
                return false;
            }

            const size_t nul = name.find('\0');
            if (nul != std::string::npos) {
                name.resize(nul);
            }

            name = Trim(name);
            return !name.empty();
        }

        APatchScanResult APatchScanner::Scan(int android_api_level) {
            // 创建默认结果对象，默认状态为 UNKNOWN。
            APatchScanResult result;
            result.android_api_level = android_api_level;

            try {
                // 第一步：记录并检查 kernel version。
                // 即使版本超出已验证范围，我们仍可能继续执行通用用户空间探针。
                const bool kernel_version_valid = AddKernelVersionContext(result);

                // 低于 3.18 的 kernel 在官方 APatch 支持范围之外。
                // 这类设备直接返回 UNSUPPORTED，避免把其他 Root 特征误认为 APatch。
                if (!kernel_version_valid
                    && result.state == APatchScanState::UNSUPPORTED) {
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

                // 如果已经发现有效阳性证据，则维持 DETECTED 状态。
                if (result.max_score > 0) {
                    result.state = APatchScanState::DETECTED;
                    return result;
                }

                // 如果当前 kernel 超过官方最高验证范围，则没有阳性证据时仍保持 UNKNOWN。
                if (result.kernel_major > kMaximumKernelMajor
                    || (result.kernel_major == kMaximumKernelMajor
                    && result.kernel_minor > kMaximumKernelMinor)) {
                    result.state = APatchScanState::UNKNOWN;
                    return result;
                }

                // 如果关键 procfs / filesystem 数据都不可观察，则不能安全地声明 CLEAN。
                if (!result.proc_observable && !result.filesystem_observable) {
                    result.state = APatchScanState::UNKNOWN;
                    return result;
                }

                // 所有可执行探针都没有发现阳性特征。
                result.state = APatchScanState::CLEAN;
            } catch (...) {
                // Native 层绝不能让 C++ 异常穿过 JNI 边界。
                // 发生异常时保留已经收集的证据，同时明确告诉上层“结果不完整”。
                result.state = APatchScanState::ERROR;

                AddEvidence(
                    result,
                    0,
                    "NATIVE_SCAN_EXCEPTION",
                    "APatchScanner::Scan",
                    "Native APatch 扫描过程中发生未预期异常，扫描结果可能不完整"
                );
            }

            return result;
        }

    } // namespace Root
} // namespace DroidProbe
