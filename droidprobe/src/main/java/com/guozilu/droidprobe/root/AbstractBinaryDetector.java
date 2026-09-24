package com.guozilu.droidprobe.root;

import android.content.Context;
import android.util.Log;

import com.guozilu.droidprobe.core.AbstractDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionEvidence;
import com.guozilu.droidprobe.core.DetectionResult;
import com.guozilu.droidprobe.core.DetectionStatus;
import com.guozilu.droidprobe.core.RiskLevel;

import org.jetbrains.annotations.NotNull;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 这是一个抽象类，传入 binaryName 就能完成全部操作
 * 这个类用来检查二进制文件是否存在
 * 在常见的路径和环境变量的路径中查找它们
 * 以及 which binaryName
 */
public abstract class AbstractBinaryDetector extends AbstractDetector {
    private static final String TAG = "AbstractBinaryDetector";
    private final String binaryName;

    private static final String[] KNOWN_COMMON_PATHS = {
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

    public AbstractBinaryDetector(@NotNull String id, @NotNull String binaryName) {
        super(id, DetectionCategory.ROOT);
        this.binaryName = binaryName;
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        List<DetectionEvidence> evidences = new ArrayList<>();
        // 查找常见路径以及环境变量看看有没有 magisk 文件
        for (String path : /* KNOWN_COMMON_PATHS */ getAllPaths()) {
            path = path + binaryName;
            File file = new File(path);
            if (file.exists()) {
                evidences.add(new DetectionEvidence(
                    binaryName.toUpperCase() + "_PATH",
                    path,
                    "发现 " + binaryName + " 文件"
                ));
            }
        }

        // 查看 which binaryName 的结果
        // Log.e(TAG, "[" + getWhichBinaryNameResult() + "]");
        String whichBinaryName = getWhichBinaryNameResult(binaryName);
        if (whichBinaryName != null) {
            evidences.add(new DetectionEvidence(
                "WHICH_" + binaryName.toUpperCase(),
                whichBinaryName,
                "执行 which " + binaryName + " 发现 " + binaryName + " 文件"
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

    private static List<String> getAllPaths() {
        List<String> paths = new ArrayList<>(Arrays.asList(KNOWN_COMMON_PATHS));
        // 拆解一下
        // 因为不同手机的可执行文件的目录是有差别的，KNOWN_COMMON_PATHS 只是涵盖一些普通情况和一些极端情况
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
     * which binaryName 的结果
     * @return 如果命令执行成功，那么返回命令输出的内容，否则返回 null
     */
    private static String getWhichBinaryNameResult(@NotNull String binaryName) {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"which", binaryName});
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
