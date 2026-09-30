package com.guozilu.droidprobe.root;

import com.guozilu.droidprobe.core.DetectionEvidence;
import com.guozilu.droidprobe.core.RiskLevel;

import org.jetbrains.annotations.NotNull;

import java.util.List;

/**
 * KernelSU 内核级 Root 环境检测器。
 *
 * <p>KernelSU 的主要实现位于 Linux 内核侧，普通 Android 应用并不一定能够
 * 直接读取其内核状态、内核接口或相关进程。因此，本检测器使用 JNI 调用
 * Native 探针，收集当前应用进程实际能够观察到的线索，再由 Java 层统一
 * 生成 DetectionResult。</p>
 *
 * <p>本检测器当前包含以下探测维度：</p>
 * <ul>
 *     <li>内核版本：仅作为检测上下文，不单凭版本号判断是否存在 KernelSU。</li>
 *     <li>内核模块列表：检查是否存在名称匹配的 KernelSU 模块。</li>
 *     <li>抽象 Unix Socket：检查经验证或配置的候选 IPC 名称。</li>
 *     <li>KernelSU 相关路径：检查已知路径是否可见且确实存在。</li>
 *     <li>内核符号表：在当前进程有权限读取时，查找 KernelSU 相关符号。</li>
 *     <li>旧版 prctl 接口：目前不执行有副作用的 KernelSU 命令；未经目标版本验证，
 *         不把猜测性的 prctl 返回值作为检测证据。</li>
 * </ul>
 *
 * <p><b>重要限制：</b>Native/JNI 不会自动获得高于 Java 层的系统权限，也不会绕过
 * Linux DAC、SELinux、procfs 可见性限制。未发现特征不能证明设备一定没有 KernelSU；
 * 数据源不可访问时应返回 UNKNOWN，而不是将“无法检测”解释为“未检测到”。</p>
 *
 * <p>该检测器目前属于启发式检测实现。文件路径、Socket 名称和符号名可能随
 * KernelSU 版本、分支、集成方式或设备 ROM 改变。发布前应在已知干净设备及
 * 不同 KernelSU 版本的实机上验证命中率和误报率。</p>
 */
public final class KernelSuDetector extends AbstractNativeRootDetector {
    private static final String TAG = "KernelSuDetector";

    static {
        System.loadLibrary("droidprobe");
    }

    public KernelSuDetector() {
        super("kernel_su", "KernelSU");
    }

    /**
     * 将 Native 层最高命中分值映射为 DroidProbe 的统一风险等级。
     *
     * @param riskScore Native 层返回的最高证据分值
     * @return 与分值对应的风险等级
     */
    @Override
    protected RiskLevel getRiskLevel(int riskScore) {
        if (riskScore >= 90) {
            return RiskLevel.CRITICAL;
        }
        else if (riskScore >= 75) {
            return RiskLevel.HIGH;
        }
        else if (riskScore >= 60) {
            return RiskLevel.MEDIUM_HIGH;
        }
        else if (riskScore >= 40) {
            return RiskLevel.MEDIUM;
        }
        else if (riskScore > 0) {
            return RiskLevel.LOW;
        }
        else if (riskScore == 0) {
            return RiskLevel.NONE;
        }
        else {
            return RiskLevel.UNKNOWN;
        }
    }

    /**
     * JNI 扫描入口。
     *
     * <p>Native 层向 evidences 追加 DetectionEvidence 对象，并返回最高命中分值。</p>
     * <ul>
     *     <li>0：扫描完成，未命中已配置特征。</li>
     *     <li>正数：命中至少一项特征，数值为最高证据分值。</li>
     *     <li>-1：Native 扫描发生错误。</li>
     *     <li>-2：扫描不完整或关键数据源不可观测。</li>
     * </ul>
     *
     * <p>即使返回 0，也只能说明未发现当前已知特征；对于隐藏、改名、修改过内核
     * 接口或当前没有活动守护进程的实现，仍可能无法识别。</p>
     *
     * @param evidences 用于接收 Native 层检测证据的 Java List
     * @return 最高命中分值或上述状态码
     */
    @Override
    protected native int nativeScan(@NotNull List<DetectionEvidence> evidences);
}
