package com.guozilu.droidprobe.root;

import android.util.Log;

import com.guozilu.droidprobe.core.DetectionEvidence;
import com.guozilu.droidprobe.core.DetectionResult;
import com.guozilu.droidprobe.core.DetectionStatus;
import com.guozilu.droidprobe.core.RiskLevel;
import com.guozilu.droidprobe.utils.MountInfo;
import com.guozilu.droidprobe.utils.MountUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 这个类的检测功能其实和检测 su 是类似的
 * 都是在检查 magisk 二进制以及 which magisk
 * 所以这个类就是 SuDetector 的基础上进行了一些改动
 */
public final class MagiskDetector extends AbstractRootBinaryDetector {
    private static final String TAG = "MagiskDetector";

    public MagiskDetector() {
        super("magisk", "magisk");
    }

    /**
     * 检查这个 binary 能不能执行，以及执行的结果是什么
     * @param rootBinaryFile 与 root 有关的二进制文件句柄
     * @return 如果能执行，执行的结果符合 root，那么返回中间采集的证据，如果都不满足返回空的 List
     */
    @Override
    protected List<DetectionEvidence> detectBinaryExecutionEvidences(File rootBinaryFile) {
        List<DetectionEvidence> evidences = new ArrayList<>();
        if (rootBinaryFile != null && rootBinaryFile.canExecute()) {
            evidences.add(new DetectionEvidence(
                "MAGISK_EXECUTION",
                rootBinaryFile.getAbsolutePath() + " can execute",
                "发现可执行的 magisk 文件"
            ));
            String executeSuResult = executeBinary();
            if (executeSuResult != null) {
                evidences.add(new DetectionEvidence(
                    "MAGISK_EXECUTED",
                    executeSuResult,
                    "执行 magisk -v 后，得到：" + executeSuResult
                ));
            }
        }
        return evidences;
    }

    /**
     * 执行 magisk -v 看看有没有效果，以及有什么效果
     * @return 如果能正常执行就返回得到的结果，否则返回 null
     */
    @Override
    protected String executeBinary() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"magisk", "-v"});
            try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
                BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()))) {
                String result = reader.readLine();
                if (result != null) {
                    return result;
                }

                String error = errorReader.readLine();
                if (error != null) {
                    return error;
                }

                // 按道理来说是执行不到这里的，这两个不可能都是 null
                return "command out: " + result + ", error message: " + error;
            }
        }
        catch (IOException e) {
            Log.e(TAG, "An exception threw in MagiskDetector.executeBinary()", e);
            return null;
        }
    }

    @Override
    protected List<DetectionEvidence> detectOthers() {
        // 检查 mount source 是否异常
        List<DetectionEvidence> evidences = new ArrayList<>();
        List<MountInfo> mountInfos = MountUtils.getMounts();
        if (mountInfos == null) {
            evidences.add(new DetectionEvidence(
                "MOUNT_INFO",
                "/proc/self/mountinfo;/proc/self/mounts;mount",
                "无法获取当前进程的挂载信息"
            ));
            return evidences;
        }
        for (MountInfo mountInfo : mountInfos) {
            if ("magisk".equalsIgnoreCase(mountInfo.getMountSource())) {
                evidences.add(new DetectionEvidence(
                    "MOUNT_SOURCE",
                    mountInfo.getMountSource(),
                    "关键系统目录的挂载源为 magisk"
                ));
            }

            // 检查 mount point 是否异常
            String lowerCaseMountPoint = mountInfo.getMountPoint().toLowerCase();
            if (lowerCaseMountPoint.contains("magisk") || lowerCaseMountPoint.contains("/adb/modules/")) {
                evidences.add(new DetectionEvidence(
                    "MOUNT_POINT",
                    mountInfo.getMountPoint(),
                    "关键系统目录的挂载目标路径为 magisk 或者 magisk 模块"
                ));
            }
        }
        return evidences;
    }
}
