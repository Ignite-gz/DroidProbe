package com.guozilu.droidprobe.root;

import android.content.Context;

import com.guozilu.droidprobe.core.AbstractDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionEvidence;
import com.guozilu.droidprobe.core.DetectionResult;
import com.guozilu.droidprobe.core.DetectionStatus;
import com.guozilu.droidprobe.core.RiskLevel;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;

/**
 * 一个抽象类，nativeScan 方法返回分数，然后 override getRiskLevel 方法定义分数对应 RiskLevel
 * 主要用于，检测全在 Native，并且 native 检测之后返回分数的情况下
 * Java 层重写 getRiskLevel 就能分数分层
 */
public abstract class AbstractNativeRootDetector extends AbstractDetector {
    private static final String TAG = "AbstractNativeRootDetector";

    /**
     * Native 扫描失败时的返回码。
     *
     * <p>负数为状态码，非负数为最高命中分值。Java 层必须先判断负数，
     * 再进行风险等级映射。</p>
     */
    private static final int NATIVE_SCAN_ERROR = -1;
    private static final int NATIVE_SCAN_INCOMPLETE = -2;

    /** 检测的类型，如 APatch、KernelSU，用于在 DetectionEvidence 中报告消息使用 */
    private final String detectionType;

    public AbstractNativeRootDetector(@NotNull String id, @NotNull String detectionType) {
        super(id, DetectionCategory.ROOT);
        this.detectionType = detectionType;
    }

    @Override
    protected final DetectionResult doDetect(Context context) {
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
                detectionType + " Native 探针执行失败，当前检测结果不可用"
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
                "Native 层未能完成扫描，无法确认 " + detectionType + " 检测结果"
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
            return createResult(DetectionStatus.UNKNOWN, RiskLevel.UNKNOWN, evidences);
        }

        // 即使 riskScore == 0 也只是扫描完成但未命中当前已配置的 KernelSU 特征。
        // 这只表示“未发现已知特征”，不代表可以排除所有隐藏或修改过的实现。
        if (riskScore == 0) {
            return createResult(DetectionStatus.NOT_DETECTED, RiskLevel.NONE, evidences);
        }

        return createResult(DetectionStatus.DETECTED, getRiskLevel(riskScore), evidences);
    }

    /**
     * 统一创建检测结果，避免在各个分支中重复填写检测器 ID 和分类。
     */
    private DetectionResult createResult(@NotNull DetectionStatus status, @NotNull RiskLevel riskLevel,
        @Nullable List<DetectionEvidence> evidences) {
        return new DetectionResult(getId(), getCategory(), status, riskLevel, evidences);
    }

    /**
     * 将 Native 层最高命中分值映射为 DroidProbe 的统一风险等级。
     * @param riskScore Native 层返回的最高证据分值
     * @return 与分值对应的风险等级
     */
    protected abstract RiskLevel getRiskLevel(int riskScore);

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
    protected abstract int nativeScan(@NotNull List<DetectionEvidence> evidences);
}
