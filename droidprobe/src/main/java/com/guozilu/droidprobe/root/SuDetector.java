package com.guozilu.droidprobe.root;

import android.content.Context;
import android.util.Log;

import com.guozilu.droidprobe.core.AbstractDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionEvidence;
import com.guozilu.droidprobe.core.DetectionResult;
import com.guozilu.droidprobe.core.DetectionStatus;
import com.guozilu.droidprobe.core.RiskLevel;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 检查 su 文件存不存在，不会去尝试执行 su 命令
 */
public final class SuDetector extends AbstractDetector {
    private static final String TAG = "SuDetector";

    // 这些是可能的静态路径
    // 那肯定考虑到不同系统不同root方式不一样，但是肯定是加入了环境变量的，所以应该把环境变量也加入进去
    private static final String[] SU_PATHS = {
        "/data/local/",
        "/data/local/bin/",
        "/data/local/xbin/",
        "/sbin/",
        "/su/bin/",
        "/system/bin/",
        "/system/bin/.ext/",
        "/system/bin/failsafe/",
        "/system/sd/xbin/",
        "/system/usr/we-need-root/",
        "/system/xbin/",
        "/system_ext/bin/",
        "/cache/",
        "/data/",
        "/dev/",
        "/vendor/bin/",
        "/data/adb/"
    };

    public SuDetector() {
        super("su", DetectionCategory.ROOT);
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        List<DetectionEvidence> evidence = new ArrayList<>();
        for (String path : /* SU_PATHS */ getAllSuPaths()) {
            path = path + "su";
            File file = new File(path);
            if (file.exists()) {
                evidence.add(new DetectionEvidence(
                    "SU_PATH",
                    path,
                    "发现 su 文件"
                ));
            }
        }
        if (evidence.isEmpty()) {
            return new DetectionResult(
                getId(),
                getCategory(),
                DetectionStatus.NOT_DETECTED,
                RiskLevel.NONE,
                evidence
            );
        }
        return new DetectionResult(
            getId(),
            getCategory(),
            DetectionStatus.DETECTED,
            RiskLevel.HIGH,
            evidence
        );
    }

    private static List<String> getAllSuPaths() {
        List<String> paths = new ArrayList<>(Arrays.asList(SU_PATHS));
        // Log.i(TAG, Objects.requireNonNull(System.getenv("PATH")));
        // 拆解一下
        // 因为不同手机的可执行文件的目录是有差别的，SU_PATHS 只是涵盖一些普通情况和一些极端情况
        // 读取系统的 PATH 才能真正知道所有的可执行目录中哪
        String systemPaths = System.getenv("PATH");
        if (systemPaths == null || systemPaths.isEmpty()) {
            return paths;
        }
        for (String systemPath : systemPaths.split(":")) {
            if (!systemPath.endsWith("/")) {
                systemPath += "/";
            }
            if (!paths.contains(systemPath)) {
                paths.add(systemPath);
            }
        }

        return paths;
    }
}
