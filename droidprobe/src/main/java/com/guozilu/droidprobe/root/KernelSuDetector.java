package com.guozilu.droidprobe.root;

import android.content.Context;
import android.util.Log;

import com.guozilu.droidprobe.core.AbstractDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionResult;
import com.guozilu.droidprobe.core.DetectionStatus;
import com.guozilu.droidprobe.core.RiskLevel;
import com.guozilu.droidprobe.core.DetectionEvidence;

import java.util.ArrayList;
import java.util.List;

/**
 * KernelSU 底层探针
 * <p>
 * 为什么不使用 Java 纯文件扫描？
 * 因为 KernelSU 运行在内核态（Ring 0），并默认开启隔离。
 * 纯 Java 层的文件 IO 会被内核直接欺骗（OverlayFS 卸载）。
 * 必须依赖 C++ NDK 发起底层的 prctl 系统调用与域套接字侧信道探测。
 */
public class KernelSuDetector extends AbstractDetector {
    private static final String TAG = "KernelSuDetector";

    static {
        System.loadLibrary("droidprobe");
    }

    public KernelSuDetector() {
        super("kernel_su", DetectionCategory.ROOT);
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        // 创建一个空列表，通过 JNI 传给底层。
        // 为什么这样做？避免 C++ 层构建复杂的 Java 集合，而是让 C++ 直接向这个列表 add 元素，降低 JNI 复杂度。
        List<DetectionEvidence> evidences = new ArrayList<>();

        // 调用底层探针，返回累计威胁分
        int riskScore = nativeScan(evidences);

        DetectionStatus status;
        RiskLevel riskLevel;

        // 根据 C++ 回传的分数进行精细的梯级风控定性
        if (riskScore >= 80) {
            // 80分代表实锤：内核调用异常(prctl) 或 发现特有内核符号
            // 这在原厂 Android 内核中绝对不可能发生，直接判定为致命风控
            status = DetectionStatus.DETECTED;
            riskLevel = RiskLevel.CRITICAL;
        }
        else if (riskScore >= 60) {
            // 60分代表强特征：抓到了 KernelSU 守护进程的跨进程通信套接字
            // 极度可疑，但可能只是残留进程，故状态定为 DETECTED，但等级拉高
            status = DetectionStatus.DETECTED;
            riskLevel = RiskLevel.MEDIUM_HIGH;
        }
        else if (riskScore >= 40) {
            // 40分代表弱特征：在 /data/adb/ 等目录发现 KSU 的工作文件夹
            // 可能是用户曾安装过但已卸载，作为中危环境标签上报
            status = DetectionStatus.NOT_DETECTED;
            riskLevel = RiskLevel.MEDIUM;
        }
        else if (riskScore > 0) {
            // 兜底的低分异常
            status = DetectionStatus.NOT_DETECTED;
            riskLevel = RiskLevel.LOW;
        }
        else {
            // 0分，内核非常纯净
            status = DetectionStatus.NOT_DETECTED;
            riskLevel = RiskLevel.NONE;
        }

        return new DetectionResult(getId(), getCategory(), status, riskLevel, evidences);
    }

    /**
     * Native 底层扫描接口
     * @param evidences 用于接收 C++ 生成证据的容器
     * @return 风险分数 (0-100+)
     */
    private native int nativeScan(List<DetectionEvidence> evidences);
}
