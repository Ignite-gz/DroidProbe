package com.guozilu.droidprobe.root;

import android.content.Context;
import android.util.Log;

import com.guozilu.droidprobe.core.AbstractDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionEvidence;
import com.guozilu.droidprobe.core.DetectionResult;
import com.guozilu.droidprobe.core.DetectionStatus;
import com.guozilu.droidprobe.core.RiskLevel;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 这个类的检测功能其实和检测 su 是类似的
 * 都是在检查 magisk 二进制以及 which magisk
 */
public final class MagiskDetector extends AbstractDetector {
    private static final String TAG = "MagiskDetector";

    // 这些是可能的静态路径
    // 那肯定考虑到不同系统不同root方式不一样，但是肯定是加入了环境变量的，所以应该把环境变量也加入进去
    private static final String[] MAGISK_PATHS = {
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

    public MagiskDetector() {
        super("magisk", DetectionCategory.ROOT);
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        List<DetectionEvidence> evidences = new ArrayList<>();
        // 查找常见路径以及环境变量看看有没有 magisk 文件
        for (String path : /* MAGISK_PATHS */ getAllMagiskPaths()) {
            path = path + "magisk";
            File file = new File(path);
            if (file.exists()) {
                evidences.add(new DetectionEvidence(
                    "MAGISK_PATH",
                    path,
                    "发现 magisk 文件"
                ));
            }
        }

        // 查看 which magisk 的结果
        // Log.e(TAG, "[" + getWhichMagiskResult() + "]");
        String whichMagisk = getWhichMagiskResult();
        if (whichMagisk != null) {
            evidences.add(new DetectionEvidence(
                "WHICH_MAGISK",
                whichMagisk,
                "执行 which magisk 发现 magisk 文件"
            ));
        }

        if (evidences.isEmpty()) {
            return new DetectionResult(
                getId(),
                getCategory(),
                DetectionStatus.NOT_DETECTED,
                RiskLevel.NONE,
                evidences
            );
        }
        return new DetectionResult(
            getId(),
            getCategory(),
            DetectionStatus.DETECTED,
            RiskLevel.HIGH,
            evidences
        );
    }

    private static List<String> getAllMagiskPaths() {
        List<String> paths = new ArrayList<>(Arrays.asList(MAGISK_PATHS));
        // 拆解一下
        // 因为不同手机的可执行文件的目录是有差别的，MAGISK_PATHS 只是涵盖一些普通情况和一些极端情况
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

    /**
     * which magisk 的结果
     * @return 如果命令执行成功，那么返回命令输出的内容，否则返回 null
     */
    private static String getWhichMagiskResult() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"which", "magisk"});
            try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
                return reader.readLine();
            }
        }
        catch (IOException e) {
            Log.e(TAG, "An exception was caught in MagiskDetector.getWhichMagiskResult()", e);
            return null;
        }
    }
}
