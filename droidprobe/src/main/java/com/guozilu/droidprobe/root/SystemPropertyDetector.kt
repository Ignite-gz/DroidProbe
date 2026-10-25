package com.guozilu.droidprobe.root;

import android.content.Context;
import android.os.Build;

import com.guozilu.droidprobe.core.AbstractDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionEvidence;
import com.guozilu.droidprobe.core.DetectionResult;
import com.guozilu.droidprobe.core.DetectionStatus;
import com.guozilu.droidprobe.core.RiskLevel;
import com.guozilu.droidprobe.utils.SystemPropertiesUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * 这个类检查危险的 prop
 * 包括：ro.debuggable 和 ro.secure
 * 我们认为 ro.debuggable 为 0 并且 ro.secure 为 1 时这个类的检测才算通过
 * ro.debuggable 用来判断系统是否为 eng/userdebug 等可调试构建
 * ro.secure 用来检查 adb 的安全沙箱限制，如果其值为 0，说明直接 adb shell 进入就是 root
 * 不过难搞的一点就是，这两个属性在安卓13的环境上是系统禁止读取的，
 * 那么在低于安卓13的环境上，如果这两个属性读不出来，就认为是低风险（如果误报则会改进策略）
 * 在安卓13或者更高版本的系统上，则将使用 Build.TYPE 也就是 ro.build.type
 * 而没有使用 BUild.TAGS 也就是 test-keys 或者 release-keys，因为这不能说明设备 root 了
 * 后面会有 test-keys 的检测可能再用到它
 */
public final class SystemPropertyDetector extends AbstractDetector {
    private static final String TAG = "SystemPropertyDetector";

    public SystemPropertyDetector() {
        super("system_property", DetectionCategory.ROOT);
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return evaluateLessTiramisu();
        }
        else {
            return evaluateGreaterEqualTiramisu();
        }
    }

    // 低于安卓13的环境
    private DetectionResult evaluateLessTiramisu() {
        DetectionStatus detectionStatus = DetectionStatus.NOT_DETECTED;
        RiskLevel riskLevel = RiskLevel.NONE;
        List<DetectionEvidence> evidences = new ArrayList<>();

        String debuggable = SystemPropertiesUtils.getprop("ro.debuggable");
        String secure = SystemPropertiesUtils.getprop("ro.secure");

        // 都读取到了
        if (debuggable != null && secure != null) {
            if (debuggable.equals("1") || secure.equals("0")) {
                detectionStatus = DetectionStatus.DETECTED;
                riskLevel = RiskLevel.CRITICAL;
                if (debuggable.equals("1")) {
                    evidences.add(new DetectionEvidence(
                        "SYSTEM_PROPERTY",
                        "ro.debuggable",
                        "ro.debuggable == 1"
                    ));
                }
                if (secure.equals("0")) {
                    evidences.add(new DetectionEvidence(
                        "SYSTEM_PROPERTY",
                        "ro.secure",
                        "ro.secure == 0"
                    ));
                }
            }
        }
        else {  // 有一个或者两个没读取到
            detectionStatus = DetectionStatus.UNKNOWN;
            riskLevel = RiskLevel.UNKNOWN;
            evidences.add(new DetectionEvidence(
                "SYSTEM_PROPERTY",
                "ro.debuggable, ro.secure",
                "低版本 Android 无法读取预期的系统属性"
            ));

            if (debuggable != null && debuggable.equals("1")) { // 读取到了 debuggable
                detectionStatus = DetectionStatus.DETECTED;
                riskLevel = RiskLevel.CRITICAL;
                evidences.add(new DetectionEvidence(
                    "SYSTEM_PROPERTY",
                    "ro.debuggable",
                    "ro.debuggable == 1"
                ));
            }
            else if (secure != null && secure.equals("0")) {    // 读取到了 secure
                detectionStatus = DetectionStatus.DETECTED;
                riskLevel = RiskLevel.CRITICAL;
                evidences.add(new DetectionEvidence(
                    "SYSTEM_PROPERTY",
                    "ro.secure",
                    "ro.secure == 0"
                ));
            }
        }

        // 最后再判断 ro.build.type == user 的问题
        if (!Build.TYPE.equals("user")) {   // TYPE = getString("ro.build.type")
            detectionStatus = DetectionStatus.DETECTED;
            riskLevel = RiskLevel.CRITICAL;
            evidences.add(new DetectionEvidence(
                "SYSTEM_PROPERTY",
                "ro.build.type",
                "ro.build.type != user"
            ));
        }

        return new DetectionResult(getId(), getCategory(), detectionStatus, riskLevel, evidences);
    }

    // 安卓13或者更高版本
    private DetectionResult evaluateGreaterEqualTiramisu() {
        DetectionStatus detectionStatus = DetectionStatus.NOT_DETECTED;
        RiskLevel riskLevel = RiskLevel.NONE;
        List<DetectionEvidence> evidences = new ArrayList<>();

        String debuggable = SystemPropertiesUtils.getprop("ro.debuggable");
        String secure = SystemPropertiesUtils.getprop("ro.secure");

        // 按道理来说是读不到的
        if (debuggable != null || secure != null) { // 读到了反而有点奇怪
            detectionStatus = DetectionStatus.UNKNOWN;
            riskLevel = RiskLevel.UNKNOWN;
            evidences.add(new DetectionEvidence(
                "SYSTEM_PROPERTY",
                "ro.debuggable, ro.secure",
                "高版本 Android 读取到了预期的系统属性"
            ));


            if (debuggable != null && debuggable.equals("1")) {
                detectionStatus = DetectionStatus.DETECTED;
                riskLevel = RiskLevel.CRITICAL;
                evidences.add(new DetectionEvidence(
                    "SYSTEM_PROPERTY",
                    "ro.debuggable",
                    "ro.debuggable == 1"
                ));
            }

            if (secure != null && secure.equals("0")) {
                detectionStatus = DetectionStatus.DETECTED;
                riskLevel = RiskLevel.CRITICAL;
                evidences.add(new DetectionEvidence(
                    "SYSTEM_PROPERTY",
                    "ro.secure",
                    "ro.secure == 0"
                ));
            }
        }

        if (!Build.TYPE.equals("user")) {
            detectionStatus = DetectionStatus.DETECTED;
            riskLevel = RiskLevel.CRITICAL;
            evidences.add(new DetectionEvidence(
                "SYSTEM_PROPERTY",
                "ro.build.type",
                "ro.build.type != user"
            ));
        }

        return new DetectionResult(getId(), getCategory(), detectionStatus, riskLevel, evidences);
    }
}
