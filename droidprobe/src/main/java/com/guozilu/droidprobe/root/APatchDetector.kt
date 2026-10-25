package com.guozilu.droidprobe.root;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;

import com.guozilu.droidprobe.core.AbstractDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionEvidence;
import com.guozilu.droidprobe.core.DetectionResult;
import com.guozilu.droidprobe.core.DetectionStatus;
import com.guozilu.droidprobe.core.RiskLevel;

import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

/**
 * APatch 环境检测器。
 *
 * <p>APatch 是一个基于 KernelPatch 的 Android 内核级 Root 方案。
 * 官方当前文档声明其支持 ARM64，并覆盖 Linux 3.18 - 6.12 内核；
 * APatch 本身依赖 KernelPatch，因此“发现 KernelPatch”与“确认 APatch”
 * 不能简单地视为同一个结论。</p>
 *
 * <p>本检测器采用“多来源证据”模型，而不是把 su、kp、apd 等某个文件名
 * 当成绝对指纹。原因是这些用户空间组件可以被改名、移动、删除或隐藏。
 * 真正有价值的证据应该尽量来自多个相互独立的层面：</p>
 *
 * <ul>
 *     <li>Java 层：APatch Manager 包名等用户空间特征；</li>
 *     <li>Native 文件系统层：APatch 配置目录及稳定配置文件；</li>
 *     <li>Native 进程层：APatch 用户空间 daemon 的运行痕迹；</li>
 *     <li>Native 内核层：/proc/kallsyms 中经过源码验证的 KernelPatch/APatch 符号；</li>
 *     <li>Native 挂载层：APatch 当前版本可能留下的特征挂载痕迹；</li>
 *     <li>扫描完整性：区分“没有发现”和“根本看不到”。</li>
 * </ul>
 *
 * <p>注意：这个检测器是“环境检测”，不是可信计算证明。一个拥有内核级权限的
 * Root 方案理论上可以伪造用户空间观察结果。因此，未观察到特征不能被解释为
 * “绝对不存在 APatch”。</p>
 *
 * <p>实际情况：根据我的实际测试，在比较最新版本的 APatch 的 root 方案中，是根本检测不出来的，
 * 因为这毕竟是内核层面的 root 方案，目前只能检测一些老版本安卓 + 老版本 APatch，那如果想检测
 * 新版本的话，目前我还是无从下手的，也许以后会深度研究实现这个检测</p>
 */
public final class APatchDetector extends AbstractNativeRootDetector {
    private static final String TAG = "APatchDetector";

    static {
        // 加载 DroidProbe 的 Native 库，后续 nativeScanAPatch() 会由 JNI 层实现。
        System.loadLibrary("droidprobe");
    }

    public APatchDetector() {
        // APatch 本质上属于 Root / kernel-root 环境，因此归入 ROOT 分类。
        super("apatch", "APatch");
    }

    @Override
    protected RiskLevel getRiskLevel(int riskScore) {
        if (riskScore >= 85) {
            return RiskLevel.CRITICAL;
        }
        else if (riskScore >= 65) {
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
