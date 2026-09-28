//
// Created by ignite on 9/28/26.
//

#ifndef DROIDPROBE_KERNEL_SU_DETECTOR_H
#define DROIDPROBE_KERNEL_SU_DETECTOR_H

#include <jni.h>

namespace DroidProbe {
    class KernelSuScanner {
    public:
        /**
         * 核心调度器：执行所有探测项
         * @param env JNI 环境指针
         * @param java_evidence_list Java 传进来的 ArrayList 对象，也就是 List<DetectionEvidence>
         * @return 累加的威胁分数
         */
        static int ScanAndReport(JNIEnv* env, jobject evidences);

    private:
         /**
         * JNI 数据回调器：负责实例化 Evidence 并 add 到 Java 列表
         * 为什么抽离？为了集中管理 DeleteLocalRef，防止 JNI 内存泄漏。
         * @param env JNIEnv
         * @param list 要添加元素的 List 对象，其实就是 List<DetectionEvidence> evidences
         * @param list_cls Java List 类
         * @param list_add_mid Java List 类的 add 方法
         * @param ev_cls Java DetectionEvidence 类
         * @param ev_ctor_mid Java DetectionEvidence 类的构造方法
         * @param type Java DetectionEvidence 类的构造方法的参数，为这个证据的类型
         * @param value Java DetectionEvidence 类的构造方法的参数，为这个证据的值
         * @param description Java DetectionEvidence 类的构造方法的参数，为这个证据的描述
         */
        static void AddJavaEvidence(JNIEnv* env, jobject list, jclass list_cls,
            jmethodID list_add_mid, jclass ev_cls, jmethodID ev_ctor_mid,
            const char* type, const char* value, const char* description);

        // 四大探测维度
        /**
         * @brief 检测 prctl 系统调用是否被 KernelSU 劫持，识别内核态 Hook 异常
         *
         * @details KernelSU 会在内核层劫持 prctl 系统调用，作为内核模块与上层应用通信的入口。
         *          检测原理：传入非法高位魔法命令 0xDEADBEEF，标准原生内核处理该非法 prctl 命令时，
         *          必定返回 -1，并且 errno 设置为 EINVAL(无效参数)。
         *          如果返回值不为 -1，或者 errno 不是 EINVAL，代表 prctl 已经被内核模块 Hook / 劫持，
         *          判定设备存在 KernelSU 类内核Root环境。
         *
         * @param env JNIEnv* JNI调用环境指针
         * @param list jobject 证据集合 Java List 对象，也就是 List<DetectionEvidence> evidences，检测出异常时会向该容器追加检测证据
         * @param list_cls jclass Java List 类引用
         * @param list_add_mid jmethodID List.add() 方法 ID，用于添加证据项
         * @param ev_cls jclass DetectionEvidence 类引用
         * @param ev_ctor_mid jmethodID DetectionEvidence 的构造函数 MethodID
         *
         * @return int 状态码
         *         - 0：未检测异常，prctl行为符合原生内核
         *         - 80：极高危，实锤prctl系统调用被劫持，存在KernelSU类内核劫持环境
         *
         * @note 该检测属于系统调用行为指纹检测；仅针对KernelSU prctl劫持逻辑，
         *       其他Root方案(Magisk普通模式等)不会触发该特征。
         *       调用前会设置errno=0，依靠prctl返回值 + errno共同做判定，不能仅依靠返回值。
         */
        static int CheckSyscallAnomaly(JNIEnv* env, jobject list, jclass list_cls,
            jmethodID list_add_mid, jclass ev_cls, jmethodID ev_ctor_mid);

        /**
         * @brief 扫描 /proc/net/unix 抽象Unix套接字，检测KernelSU守护进程ksud通信套接字痕迹
         *
         * @details KernelSU 的守护进程 ksud 使用 Linux 抽象命名空间 Unix socket 完成内核模块、管理APP之间IPC通信。
         *          抽象套接字以 @ 作为名字前缀，不会在文件系统生成实体文件，但全部会暴露在 /proc/net/unix。
         *          检测原理：逐行读取解析 /proc/net/unix，查找包含 @ksud、@kernelsu 的套接字名字；
         *          一旦命中特征字符串，说明系统存在正在运行的 ksud 守护进程，属于KernelSU强特征证据。
         *
         * @param env JNIEnv* JNI调用环境指针
         * @param list jobject 证据集合 Java List 对象，也就是 List<DetectionEvidence> evidences，检测命中时向容器追加检测证据
         * @param list_cls jclass Java List 类引用
         * @param list_add_mid jmethodID List.add() 方法ID，用于调用List.add添加证据项
         * @param ev_cls jclass DetectionEvidence 类引用
         * @param ev_ctor_mid jmethodID DetectionEvidence 的构造函数 MethodID
         *
         * @return int 状态码
         *         - 0：未发现KSU抽象套接字特征
         *         - 60：中高危，Android 9+ 环境中可以读取 /proc/net/unix，但没查找到 ksu 相关的 unix 套接字信息
         *         - 80：极高危，命中 ksud 抽象 IPC 套接字，设备存在运行中 KernelSU 环境
         *
         * @note 该检测基于procfs文件系统痕迹；仅针对KernelSU；Magisk普通模式不会产生该套接字特征。
         *       遍历全部条目，将所有有关的抽象 unix 套接字证据都记录进去，库调用者可以修改这个逻辑，让其找到第一个就立刻返回
         *       规避局限：如果攻击者修改ksud源码、重命名套接字名称，该检测会失效。
         */
        static int CheckAbstractSockets(JNIEnv* env, jobject list, jclass list_cls,
            jmethodID list_add_mid, jclass ev_cls, jmethodID ev_ctor_mid);

        /**
         * @brief 检测 /data/adb 下 KernelSU 特征路径，同时通过可访问性反向判定系统权限篡改
         *
         * @details 原生 Android 11+ 环境下，普通第三方应用受 DAC 权限与 SELinux 双重限制，
         *          完全无法触及 /data/adb 目录，access 调用必然返回 -1 且 errno 为 EACCES。
         *          若能成功访问该目录下的路径（无论文件是否存在），本身就说明系统权限配置已被修改，
         *          是 Root 或系统篡改的强特征；若特征文件真实存在，则进一步实锤 KernelSU 残留。
         *          使用 access(F_OK) 仅做 inode 存在性校验，无需读写权限。
         *
         * @param env JNIEnv* JNI调用环境指针
         * @param list jobject 证据集合 Java List 对象，检测命中时向容器追加检测证据
         * @param list_cls jclass Java List 类引用
         * @param list_add_mid jmethodID List.add() 方法ID
         * @param ev_cls jclass DetectionEvidence 类引用
         * @param ev_ctor_mid jmethodID DetectionEvidence 的构造函数 MethodID
         *
         * @return int 状态码
         *         -  0：符合原生权限拦截，未检测到异常
         *         - 60：低危，可访问 /data/adb 目录但未找到特征文件，系统权限策略已被篡改
         *         - 80：中危，检测到 KernelSU 专属目录/文件残留，且系统权限已突破（可以访问 /data/adb/ 中的文件）
         *
         * @note 本检测属于「文件系统痕迹 + 权限异常」双重判定；命中则置信度极高，未命中不代表无Root。
         *       Android 11+ SELinux enforcing 原生环境必定返回 EACCES，非 EACCES 均视为异常。
         *       绕过方式：修改 KSU 安装路径、保留默认权限策略仅修改内核层，或者魔改源码掩盖特征，可绕过该检测。
         *       仅作为辅助增强证据，核心判定仍依赖 prctl 系统调用劫持、抽象套接字检测。
         *       遍历全部条目，将所有命中的路径加入到证据中。
         */
        static int CheckSuspiciousFiles(JNIEnv* env, jobject list, jclass list_cls,
            jmethodID list_add_mid, jclass ev_cls, jmethodID ev_ctor_mid);

        /**
         * @brief 读取并扫描 /proc/kallsyms 内核符号表，检测 KernelSU 内核符号特征
         *
         * @details /proc/kallsyms 由内核导出，记录全部内核符号（函数、全局变量）的地址与符号名。
         *          KernelSU 无论是以 LKM 模块加载，还是内核补丁形式编译进内核，都会注册大量以 ksu_ 开头的内核符号。
         *          在 kptr_restrict 未严格限制符号导出的环境下，用户态可直接读取该虚拟文件。
         *          通过匹配 " ksu_"（前置空格规避子串误命中）识别 KSU 注入符号，作为内核层被篡改的证据。
         *          仅做字符串匹配，不解析符号地址，文件打开失败时直接判定无结果。
         *
         * @param env JNIEnv* JNI调用环境指针
         * @param list jobject 证据集合 Java List 对象，命中时向容器追加检测证据
         * @param list_cls jclass Java List 类引用
         * @param list_add_mid jmethodID List.add() 方法ID
         * @param ev_cls jclass DetectionEvidence 类引用
         * @param ev_ctor_mid jmethodID DetectionEvidence 的构造函数 MethodID
         *
         * @return int 状态码
         *         -  0：文件不可读或未扫描到 ksu_ 相关内核符号，无证据
         *         - 60：中高危，SELinux 为 Permissive
         *         - 80：极高危，成功匹配到 KernelSU 专属内核符号，内核层存在 KSU 痕迹
         *
         * @note 本检测依赖 /proc/kallsyms 的可读权限；若内核配置 kptr_restrict、或 KSU 开启符号隐藏、
         *       魔改修改符号前缀，本检测会直接绕过失效。
         *       属于辅助内核痕迹证据，未命中不能证明不存在 KernelSU，建议配合 prctl、抽象套接字等检测联合判定。
         *       遍历全部条目，将所有命中的 ksu_ 符号上报证据。
         */
        static int CheckKallsyms(JNIEnv* env, jobject list, jclass list_cls,
            jmethodID list_add_mid, jclass ev_cls, jmethodID ev_ctor_mid);
    };
} // namespace DroidProbe

#endif // DROIDPROBE_KERNEL_SU_DETECTOR_H
