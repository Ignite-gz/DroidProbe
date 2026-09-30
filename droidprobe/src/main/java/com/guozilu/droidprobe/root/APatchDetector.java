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
 * 新版本的话，目前我还是无从下手的，也许以后就可以检测了</p>
 */
public final class APatchDetector extends AbstractDetector {
    private static final String TAG = "APatchDetector";

    static {
        System.loadLibrary("droidprobe");
    }

    public APatchDetector() {
        super("apatch", DetectionCategory.ROOT);
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        // 创建统一的证据列表；Java 层和 Native 层最终都把检测结果合并到这里。
        List<DetectionEvidence> evidences = new ArrayList<>();

        // 把当前 Android API Level 传给 Native，而不是让 Native 依赖 NDK API 的 Android 版本查询接口。
        // 这样可以保持 minSdk 23 的兼容性，并且让 Native 只负责 Linux / procfs / kernel 检测。
        APatchNativeResult nativeResult = nativeScanAPatch(Build.VERSION.SDK_INT);

        // 将 Native 返回的结构化证据逐项追加到统一结果列表。
        if (nativeResult != null) {
            nativeResult.appendEvidenceTo(evidences);
        }

        // Java 层和 Native 层都没有任何检测分数时，仍然要考虑“扫描是否完整”。
        if (nativeResult == null) {
            evidences.add(new DetectionEvidence(
                "NATIVE_SCAN_UNAVAILABLE",
                "droidprobe",
                "APatch Native 检测器没有返回结果，无法确认当前环境"
            ));

            return new DetectionResult(
                getId(),
                getCategory(),
                DetectionStatus.UNKNOWN,
                RiskLevel.LOW,
                evidences
            );
        }

        int score = nativeResult.maxScore;

        // Native 扫描发现一个已经由源码验证的 KernelPatch/APatch 内核强证据时，
        // 其分值会高于管理器包名等弱证据。
        if (score >= 85) {
            return new DetectionResult(
                getId(),
                getCategory(),
                DetectionStatus.DETECTED,
                RiskLevel.CRITICAL,
                evidences
            );
        }

        if (score >= 65) {
            return new DetectionResult(
                getId(),
                getCategory(),
                DetectionStatus.DETECTED,
                RiskLevel.MEDIUM_HIGH,
                evidences
            );
        }

        if (score >= 40) {
            return new DetectionResult(
                getId(),
                getCategory(),
                DetectionStatus.DETECTED,
                RiskLevel.MEDIUM,
                evidences
            );
        }

        if (score > 0) {
            return new DetectionResult(
                getId(),
                getCategory(),
                DetectionStatus.UNKNOWN,
                RiskLevel.LOW,
                evidences
            );
        }

        // Native 将 unsupported kernel / 不可观测状态等情况编码到 scanState 中。
        // 如果扫描能力不完整，不能把“没看到”直接解释成“没有 APatch”。
        if (nativeResult.scanState == NativeScanState.UNKNOWN
            || nativeResult.scanState == NativeScanState.UNSUPPORTED) {
            return new DetectionResult(
                getId(),
                getCategory(),
                DetectionStatus.UNKNOWN,
                RiskLevel.LOW,
                evidences
            );
        }

        // 所有可观察探针都完成并且没有发现阳性特征时，才返回 NOT_DETECTED。
        return new DetectionResult(
            getId(),
            getCategory(),
            DetectionStatus.NOT_DETECTED,
            RiskLevel.NONE,
            evidences
        );
    }

    /**
     * Native 层返回的扫描状态。
     */
    private static final class NativeScanState {
        /** 所有可观察探针完成，并且没有检测到 APatch 特征。 */
        static final int CLEAN = 0;
        /** 至少发现一项 APatch / KernelPatch 相关证据。 */
        static final int DETECTED = 1;
        /** 系统信息或关键 procfs 数据不可观察，不能排除 APatch。 */
        static final int UNKNOWN = 2;
        /** 当前内核不在 APatch 官方声明的验证范围内。 */
        static final int UNSUPPORTED = 3;
        /** Native 扫描自身发生错误。 */
        static final int ERROR = 4;

        private NativeScanState() {
        }
    }

    /**
     * Native 检测结果的 Java 镜像。
     *
     * <p>为了避免 C++ JNI 层频繁操作 java.util.List，Native 一次性返回结构化数组，
     * 然后 Java 再创建 DetectionEvidence。这种方式也更容易维护和单元测试。</p>
     */
    private static final class APatchNativeResult {
        /** Native 扫描最高证据分值。 */
        final int maxScore;
        /** Native 扫描状态。 */
        final int scanState;
        /** Native 返回的规则名。 */
        final String[] ruleNames;
        /** Native 返回的目标值。 */
        final String[] targets;
        /** Native 返回的详细描述。 */
        final String[] details;

        APatchNativeResult(
            int maxScore,
            int scanState,
            String[] ruleNames,
            String[] targets,
            String[] details) {
            this.maxScore = maxScore;
            this.scanState = scanState;
            this.ruleNames = ruleNames;
            this.targets = targets;
            this.details = details;
        }

        /**
         * 把 Native 字符串数组转换成 DroidProbe 的 DetectionEvidence。
         */
        void appendEvidenceTo(List<DetectionEvidence> evidences) {
            // 防御性检查，避免错误的 Native 返回值造成数组越界。
            if (ruleNames == null || targets == null || details == null) {
                return;
            }

            int size = Math.min(ruleNames.length, Math.min(targets.length, details.length));

            for (int i = 0; i < size; i++) {
                evidences.add(new DetectionEvidence(
                    ruleNames[i],
                    targets[i],
                    details[i]
                ));
            }
        }
    }

    /**
     * JNI 入口。
     *
     * @param androidApiLevel 当前设备 Android API Level，例如 Android 6.0 为 23。
     * @return 结构化 Native 扫描结果；JNI 异常时可以返回 null。
     */
    private native APatchNativeResult nativeScanAPatch(int androidApiLevel);
}
