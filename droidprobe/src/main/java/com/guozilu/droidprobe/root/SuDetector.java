package com.guozilu.droidprobe.root;

import android.util.Log;

import com.guozilu.droidprobe.core.DetectionEvidence;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 检查 su 文件存不存在以及是否有可执行权限，并尝试执行 su -c id 能不能得到类似于
 * uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0 的结果
 */
public final class SuDetector extends AbstractRootBinaryDetector {
    private static final String TAG = "SuDetector";

    public SuDetector() {
        super("su", "su");
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
                "SU_EXECUTION",
                rootBinaryFile.getAbsolutePath() + " can execute",
                "发现可执行的 su 文件"
            ));
            String executeSuResult = executeBinary();
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
     * @return 如果能正常执行就返回得到的结果，否则返回 null
     */
    @Override
    protected String executeBinary() {
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

                // 按道理来说是执行不到这里的，这两个不可能都是 null
                return "command out: " + result + ", error message: " + error;
            }
        }
        catch (IOException e) {
            Log.e(TAG, "An exception threw in SuDetector.executeBinary()", e);
            return null;
        }
    }
}
