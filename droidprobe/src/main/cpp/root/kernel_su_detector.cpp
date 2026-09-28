//
// Created by ignite on 9/28/26.
//

#include "kernel_su_detector.h"

#include <cerrno>
#include <fstream>
#include <string>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <android/api-level.h>
#include "droid_probe_log.h"

/**
* 查看 Kernel Su 的运行环境要求，发现它必须运行中 Linux 内核版本高于 4.14 的环境中
* 这个函数就是检查当前 Linux 内核版本是否 >= 4.14
* @return 如果当前 Linux 内核版本大于等于 4.14 返回 true，否则返回 false
*/
static bool IsKernelVersionSupportedForKsu() {
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
}

void DroidProbe::KernelSuScanner::AddJavaEvidence(JNIEnv* env, jobject list, jclass list_cls,
                                                  jmethodID list_add_mid, jclass ev_cls,
                                                  jmethodID ev_ctor_mid, const char* type,
                                                  const char* value, const char* description) {
    // 1. 在 JNI 中创建 Java 的 String 对象
    jstring j_type = env->NewStringUTF(type);
    jstring j_value = env->NewStringUTF(value);
    jstring j_description = env->NewStringUTF(description);

    // 2. 实例化 com.guozilu.droidprobe.core.DetectionEvidence
    jobject ev_obj = env->NewObject(ev_cls, ev_ctor_mid, j_type, j_value, j_description);

    // 3. 将新创建的 Evidence 对象添加到 Java 的 ArrayList 中 (调用 List.add)
    env->CallBooleanMethod(list, list_add_mid, ev_obj);

    // 4. 销毁局部引用，防止 JNI 表容量爆满导致抛出 JNI Local Reference Table Overflow 崩溃
    env->DeleteLocalRef(j_type);
    env->DeleteLocalRef(j_value);
    env->DeleteLocalRef(j_description);
    env->DeleteLocalRef(ev_obj);
}

int DroidProbe::KernelSuScanner::CheckSyscallAnomaly(JNIEnv* env, jobject list, jclass list_cls,
                                                     jmethodID list_add_mid, jclass ev_cls,
                                                     jmethodID ev_ctor_mid) {
    // 防御性校验：避免空指针导致 JNI 崩溃
    if (!env || !list || !list_cls || !list_add_mid || !ev_cls || !ev_ctor_mid) {
        return 0;
    }

    int max_score = 0;

    // ------------------------------------------------------------------------
    // 探针 1: prctl 多 Magic 码碰撞检测 (Seccomp 安全)
    // ------------------------------------------------------------------------
    // 收集 KernelSU / APatch / Suki 等常见内核 Hook 使用的 Magic 选项值
    const std::vector<int> ksu_magics = {
        static_cast<int>(0xDEADBEEF),
        0x4321FEDC,
        0x20230222,
        0x11223344
    };

    for (int magic : ksu_magics) {
        errno = 0;
        int ret = prctl(magic, 0, 0, 0, 0);

        // 原生内核对于未知的 prctl option，必定返回 -1 且 errno 为 EINVAL (22)
        // 如果返回 >= 0，或者错误码不是 EINVAL，说明 prctl 逻辑已被内核 Hook 篡改
        if (ret >= 0 || (ret == -1 && errno != EINVAL)) {
            AddJavaEvidence(env, list, list_cls, list_add_mid, ev_cls, ev_ctor_mid,
                "SYSCALL_PRCTL_HOOK", "prctl",
                "检测到 prctl 系统调用行为异常，内核逻辑已被篡改");
            max_score = std::max(max_score, 80);
            break;
        }
    }

    // ------------------------------------------------------------------------
    // 探针 2: faccessat 模式参数校验探针 (Seccomp 安全，替代 reboot)
    // ------------------------------------------------------------------------
    // 逻辑：向 faccessat 传入非法的 mode (如 0xFFFFFFFF) 检查内核响应。
    // 原生内核在解析路径前就会校验 mode 参数，必须返回 EINVAL (22)。
    // 某些粗糙的内核 Hook 可能会优先做路径挂钩或权限判断，从而返回 ENOENT (2) 或 EACCES (13)。
    errno = 0;
    int faccess_ret = faccessat(AT_FDCWD, "/data/adb/ksu", 0xFFFFFFFF, 0);

    if (faccess_ret == 0) {
        // 非法 mode 竟然返回成功，绝对存在内核 Hook
        AddJavaEvidence(env, list, list_cls, list_add_mid, ev_cls, ev_ctor_mid,
            "SYSCALL_FACCESSAT_BYPASS", "faccessat",
            "严重异常：faccessat 传入非法 mode 依然返回成功");
        max_score = std::max(max_score, 85);
    }
    else if (errno != EINVAL) {
        // 如果错误码不是 EINVAL（比如变成了 ENOENT 或 EACCES），说明 Hook 函数提前拦截并处理了路径
        AddJavaEvidence(env, list, list_cls, list_add_mid, ev_cls, ev_ctor_mid,
            "SYSCALL_FACCESSAT_HOOK", "faccessat",
            "检测到 faccessat 系统调用返回码异常，存在内核 Hook 拦截痕迹");
        max_score = std::max(max_score, 70);
    }

    return max_score;
}

int DroidProbe::KernelSuScanner::CheckAbstractSockets(JNIEnv* env, jobject list, jclass list_cls,
                                                      jmethodID list_add_mid, jclass ev_cls,
                                                      jmethodID ev_ctor_mid) {
    // 1. 获取当前系统 Android API Level
    int api_level = android_get_device_api_level();

    errno = 0;
    std::ifstream fin("/proc/net/unix", std::ios_base::in);

    // 【场景 1】：无法打开文件
    if (!fin.is_open()) {
        // 在 Android 10+ (API 29+) 上，EACCES (13) 属于受 SELinux 保护的纯净系统正常现象
        return 0;
    }

    int max_score = 0;

    // 【场景 2】：成功打开了 /proc/net/unix
    // 判定 A：SELinux 越权检测 (仅针对 Android 10+)
    if (api_level >= __ANDROID_API_Q__) {
        AddJavaEvidence(env, list, list_cls, list_add_mid, ev_cls, ev_ctor_mid,
            "SELINUX_PROC_NET_BYPASS", "/proc/net/unix",
            "SELinux 隔离失效：普通 App 越权读取了 /proc/net/unix");
        max_score = 60; // SELinux 被解封/穿透，标记为高危
    }

    // 判定 B：扫描套接字表，寻找 KernelSU 的 IPC 守护进程特征
    std::string line;
    // 跳过表头
    if (std::getline(fin, line)) {
        while (std::getline(fin, line)) {
            std::string_view sv(line);

            // 匹配 KSU 常见的抽象套接字名称（@ksud 或 @kernelsu）
            if (sv.find("@ksud") != std::string_view::npos ||
                sv.find("@kernelsu") != std::string_view::npos) {

                std::string socketInfo = "unix_socket: " + line;
                AddJavaEvidence(env, list, list_cls, list_add_mid, ev_cls, ev_ctor_mid,
                    "ABSTRACT_SOCKET_MATCH", socketInfo.c_str(),
                    "捕获到 KernelSU IPC 守护进程套接字");

                // 抓到了确凿的 KSU 运行特征，直接提升为 80 分
                max_score = 80;
            }
        }
    }

    // 如果能 open 成功（Android 10+），但没找到具体的 @ksud 字符串，返回 SELinux 异常分 (60 分)
    // 如果是 Android 9 及以下，能 open 且没找到 ksu 字符串，返回 0 分
    return max_score;
}


int DroidProbe::KernelSuScanner::CheckSuspiciousFiles(JNIEnv* env, jobject list, jclass list_cls,
                                                      jmethodID list_add_mid, jclass ev_cls,
                                                      jmethodID ev_ctor_mid) {
    const std::vector<const char *> ksu_paths = {
        "/data/adb/ksu",
        "/data/adb/ksud",
        "/data/adb/modules/kernelsu"
    };

    int max_score = 0;

    for (const char *path: ksu_paths) {
        errno = 0;
        int res = access(path, F_OK);

        if (res == 0) {
            // 场景 1：成功访问到了文件/目录 (res == 0)
            // 意味着：路径存在，且 App 越权获取了对 /data/adb/ 的读取权限（SELinux 被解封或进程被提权）
            AddJavaEvidence(env, list, list_cls, list_add_mid, ev_cls, ev_ctor_mid,
                "KSU_PATH_ACCESSIBLE", path,
                "KSU 目录存在且突破了系统的 DAC/MAC 隔离限制");
            max_score = std::max(max_score, 80);
        }
        else if (errno == ENOENT) {
            // 场景 2：返回 ENOENT (2, 文件不存在)
            // 正常情况下，DAC (0700) 会在父目录拦截并返回 EACCES (13)。
            // 能拿到 ENOENT，说明 App 成功穿透了 /data/adb/ 目录！说明 SELinux/DAC 策略已被篡改（如 setenforce 0）
            AddJavaEvidence(env, list, list_cls, list_add_mid, ev_cls, ev_ctor_mid,
                "SELINUX_PERMISSIVE_ANOMALY", path,
                "文件不存在，但系统安全隔离失效：普通 App 越权穿透了敏感系统目录");
            max_score = std::max(max_score, 60);
        }
        // 场景 3：errno == EACCES (13)
        // 这是所有纯净 Android 版本（API 24 ~ API 35+）上的正常隔离表现，不作处理。
    }

    return max_score;
}

int DroidProbe::KernelSuScanner::CheckKallsyms(JNIEnv* env, jobject list, jclass list_cls,
                                               jmethodID list_add_mid, jclass ev_cls,
                                               jmethodID ev_ctor_mid) {
    int api_level = android_get_device_api_level();

    errno = 0;
    std::ifstream fin("/proc/kallsyms", std::ios_base::in);

    // 判定 1：文件能够成功打开
    if (fin.is_open()) {
        int detected_score = 0;

        // 在 Android 8.0+ (API 26+) 上，SELinux 严格禁止普通 App 打开 /proc/kallsyms
        // 如果成功 open，说明 SELinux 已经被关闭(Permissive) 或 策略被全局 Patch 穿透
        if (api_level >= __ANDROID_API_O__) {
            AddJavaEvidence(env, list, list_cls, list_add_mid, ev_cls, ev_ctor_mid,
                "SELINUX_KALLSYMS_BYPASS", "/proc/kallsyms",
                "SELinux 隔离异常：普通 App 越权打开了 /proc/kallsyms");
            detected_score = 60; // SELinux 被破防，定性为高危
        }

        // 判定 2：读取内容，检查是否存在 KSU 注入符号
        std::string line;
        while (std::getline(fin, line)) {
            // 过滤 ksu_ 或 kernelsu_ 关键字
            if (line.find(" ksu_") != std::string::npos ||
                line.find(" kernelsu_") != std::string::npos) {
                AddJavaEvidence(env, list, list_cls, list_add_mid, ev_cls, ev_ctor_mid,
                    "KALLSYMS_KSU_SYMBOL", "/proc/kallsyms",
                    "在内核符号表中捕获到 KernelSU 注入函数");
                return 80; // 抓到了具体的内核函数，实锤，直接返回最高分 80
            }
        }

        // 如果 open 成功但没扫到 ksu_ 符号（可能被抹除名目），仍然返回 SELinux 异常分
        return detected_score > 0 ? detected_score : 60;
    }

    // file.is_open() 为 false 且 errno == EACCES (13)，是 Android 8.0+ 的正常隔离表现
    return 0;
}

int DroidProbe::KernelSuScanner::ScanAndReport(JNIEnv* env, jobject evidences) {
    int total_score = 0;

    jclass list_cls = env->GetObjectClass(evidences);
    jmethodID list_add_mid = env->GetMethodID(list_cls, "add", "(Ljava/lang/Object;)Z");

    jclass ev_cls = env->FindClass("com/guozilu/droidprobe/core/DetectionEvidence");
    jmethodID ev_ctor_mid = env->GetMethodID(ev_cls, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");

    // --- 开始分层探测 ---
    total_score += CheckSyscallAnomaly(env, evidences, list_cls, list_add_mid, ev_cls, ev_ctor_mid);
    total_score += CheckAbstractSockets(env, evidences, list_cls, list_add_mid, ev_cls, ev_ctor_mid);
    total_score += CheckSuspiciousFiles(env, evidences, list_cls, list_add_mid, ev_cls, ev_ctor_mid);
    total_score += CheckKallsyms(env, evidences, list_cls, list_add_mid, ev_cls, ev_ctor_mid);

    // 释放最外层的局部引用
    env->DeleteLocalRef(list_cls);
    env->DeleteLocalRef(ev_cls);

    return total_score;
}
