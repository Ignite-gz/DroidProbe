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
 * 检查 su 文件存不存在以及是否有可执行权限，并尝试执行 su -c id 能不能得到类似于
 * uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0 的结果
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
        List<DetectionEvidence> evidences = new ArrayList<>();
        // 查找常见路径以及环境变量看看有没有 su 文件
        for (String path : /* SU_PATHS */ getAllSuPaths()) {
            path = path + "su";
            evidences.addAll(detectSuPathEvidences(path));
        }

        // 查看 which su 的结果
        // Log.e(TAG, "[" + getWhichSuResult() + "]");
        String whichSu = getWhichSuResult();
        if (whichSu != null) {
            evidences.add(new DetectionEvidence(
                "WHICH_SU",
                whichSu,
                "执行 which su 发现 su 文件"
            ));
            File file = new File(whichSu);
            evidences.addAll(detectSuFileExecutionEvidences(file));
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

    private static List<String> getAllSuPaths() {
        List<String> paths = new ArrayList<>(Arrays.asList(SU_PATHS));
        // Log.i(TAG, Objects.requireNonNull(System.getenv("PATH")));
        // 拆解一下
        // 因为不同手机的可执行文件的目录是有差别的，SU_PATHS 只是涵盖一些普通情况和一些极端情况
        // 读取系统的 PATH 才能真正知道所有的可执行目录在哪
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
     * which su 的结果
     * @return 如果命令执行成功，那么返回命令输出的内容，否则返回 null
     */
    private static String getWhichSuResult() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"which", "su"});
            try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
                return reader.readLine();
            }
        }
        catch (IOException e) {
            Log.e(TAG, "An exception was caught in SuDetector.getWhichSuResult()", e);
            return null;
        }
    }

    /**
     * 检查指定 su 路径的文件是否存在，是否可执行，是否真的能直接身份变为 root
     * @param path 指定 su 的路径
     * @return 结果成立时的证据，如果都不成立则返回空的 List
     */
    private static List<DetectionEvidence> detectSuPathEvidences(String path) {
        List<DetectionEvidence> evidences = new ArrayList<>();
        File file = new File(path);
        if (file.exists()) {
            evidences.add(new DetectionEvidence(
                "SU_PATH",
                path,
                "发现 su 文件"
            ));

            evidences.addAll(detectSuFileExecutionEvidences(file));
        }
        return evidences;
    }

    /**
     * 检查这个 su 能不能执行，以及执行的结果是什么
     * @param suFile su
     * @return 如果能执行，执行的结果符合 root，那么返回中间采集的证据，如果都不满足返回空的 List
     */
    private static List<DetectionEvidence> detectSuFileExecutionEvidences(File suFile) {
        List<DetectionEvidence> evidences = new ArrayList<>();
        if (suFile.canExecute()) {
            evidences.add(new DetectionEvidence(
                "SU_EXECUTION",
                suFile.getAbsolutePath() + "can execute",
                "发现可执行的 su 文件"
            ));
            String executeSuResult = executeSu();
            if (executeSuResult != null) {
                evidences.add(new DetectionEvidence(
                    "SU_EXECUTED",
                    executeSuResult,
                    "执行 su -c id 后 " + executeSuResult
                ));
            }
        }
        return evidences;
    }

    /**
     * 执行 su -c id 看看能不能得到类似于
     * uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0 的结果
     * @return 如果能得到就返回得到的结果，否则返回 null
     */
    private static String executeSu() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", "id"});
            try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
                BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()))) {
                // 如果用户拒绝了权限，那么 result 就应该是 null，error 是 Permission denied
                // 如果用户允许了，那么 result 就应该是 uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0
                // error 是 null
                String result = reader.readLine();
                if (result != null) {
                    String[] result_split = result.split("\\s+");
                    if (result_split[0].contains("root") || result_split[0].contains("uid=0") ||
                        result_split[1].contains("root") || result_split[1].contains("gid=0") ||
                        result_split[2].contains("root") || result_split[2].contains("groups=0")) {
                        return result;
                    }
                }

                String error = errorReader.readLine();
                // 这个时候肯定是告诉我们说权限不允许，因为这个文件一定存在（执行这个函数前就找出了文件的位置）
                // 那么权限不允许说明什么叫不必多说了吧
                if (error != null) {
                    return error;
                }

                // 按道理来说是执行不到这里的
                return "command out: " + result + ", error message: " + error;
            }
        }
        catch (IOException e) {
            Log.e(TAG, "An exception threw in SuDetector.executeSu()", e);
            return null;
        }
    }
}
