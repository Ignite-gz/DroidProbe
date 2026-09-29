package com.guozilu.droidprobe.root;

import android.content.Context;

import com.guozilu.droidprobe.core.AbstractDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionEvidence;
import com.guozilu.droidprobe.core.DetectionResult;
import com.guozilu.droidprobe.core.DetectionStatus;
import com.guozilu.droidprobe.core.RiskLevel;

import java.util.ArrayList;
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
public final class KernelSuDetector extends AbstractDetector {
    private static final String TAG = "KernelSuDetector";

    static {
        System.loadLibrary("droidprobe");
    }

    /**
     * Native 扫描失败时的返回码。
     *
     * <p>负数为状态码，非负数为最高命中分值。Java 层必须先判断负数，
     * 再进行风险等级映射。</p>
     */
    private static final int NATIVE_SCAN_ERROR = -1;
    private static final int NATIVE_SCAN_INCOMPLETE = -2;

    /**
     * 检测分值采用“最高有效证据”映射，而不是把相关探针的分数直接相加。
     * 这样可以降低同一个系统现象通过多个数据源被重复计分后造成的误判。
     */
    private static final int SCORE_CRITICAL = 90;
    private static final int SCORE_HIGH = 75;
    private static final int SCORE_MEDIUM_HIGH = 60;
    private static final int SCORE_MEDIUM = 40;

    public KernelSuDetector() {
        super("kernel_su", DetectionCategory.ROOT);
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        List<DetectionEvidence> evidences = new ArrayList<>();

        // Native 层只负责采集证据和计算最高命中分值，风险等级由 Java 层统一管理。
        final int riskScore;
        try {
            riskScore = nativeScan(evidences);
        }
        catch (RuntimeException | LinkageError exception) {
            // JNI 加载、链接或调用发生异常时，不应让单个检测器影响整个扫描流程。
            evidences.add(new DetectionEvidence(
                "NATIVE_SCAN_ERROR",
                exception.getClass().getName(),
                "KernelSU Native 探针执行失败，当前检测结果不可用"
            ));
            return createResult(
                DetectionStatus.ERROR,
                RiskLevel.LOW,
                evidences
            );
        }

        if (riskScore == NATIVE_SCAN_ERROR) {
            evidences.add(new DetectionEvidence(
                "NATIVE_SCAN_ERROR",
                "nativeScan",
                "Native 层未能完成扫描，无法确认 KernelSU 检测结果"
            ));
            return createResult(DetectionStatus.ERROR, RiskLevel.LOW, evidences);
        }

        if (riskScore == NATIVE_SCAN_INCOMPLETE) {
            // 关键数据源均不可观测或扫描不完整：没有阳性结果不等于设备干净
            return createResult(DetectionStatus.UNKNOWN, RiskLevel.LOW, evidences);
        }

        if (riskScore < 0) {
            // 对未约定的负数返回码采取保守处理，避免意外映射成高风险
            evidences.add(new DetectionEvidence(
                "NATIVE_SCAN_UNKNOWN_STATUS",
                String.valueOf(riskScore),
                "Native 层返回了未知状态码，当前检测结果不可确定"
            ));
            return createResult(DetectionStatus.UNKNOWN, RiskLevel.LOW, evidences);
        }


        // 即使 riskScore == 0 也只是扫描完成但未命中当前已配置的 KernelSU 特征。
        // 这只表示“未发现已知特征”，不代表可以排除所有隐藏或修改过的实现。
        if (riskScore == 0) {
            return createResult(DetectionStatus.NOT_DETECTED, RiskLevel.NONE, evidences);
        }

        return createResult(DetectionStatus.DETECTED, getRiskLevel(riskScore), evidences);
    }

    /**
     * 将 Native 层最高命中分值映射为 DroidProbe 的统一风险等级。
     *
     * @param riskScore Native 层返回的最高证据分值
     * @return 与分值对应的风险等级
     */
    private static RiskLevel getRiskLevel(int riskScore) {
        if (riskScore >= SCORE_CRITICAL) {
            return RiskLevel.CRITICAL;
        }
        else if (riskScore >= SCORE_HIGH) {
            return RiskLevel.HIGH;
        }
        else if (riskScore >= SCORE_MEDIUM_HIGH) {
            return RiskLevel.MEDIUM_HIGH;
        }
        else if (riskScore >= SCORE_MEDIUM) {
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
     * 统一创建检测结果，避免在各个分支中重复填写检测器 ID 和分类。
     */
    private DetectionResult createResult(DetectionStatus status, RiskLevel riskLevel,
        List<DetectionEvidence> evidences) {
        return new DetectionResult(getId(), getCategory(), status, riskLevel, evidences);
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
    private native int nativeScan(List<DetectionEvidence> evidences);
}
