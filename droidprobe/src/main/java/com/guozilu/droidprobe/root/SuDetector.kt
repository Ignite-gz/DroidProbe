package com.guozilu.droidprobe.root

import android.util.Log
import com.guozilu.droidprobe.core.DetectionEvidence
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader

/**
 * 检查 su 文件存不存在以及是否有可执行权限，并尝试执行 su -c id 能不能得到类似于
 * uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0 的结果
 */
class SuDetector : AbstractRootBinaryDetector(
    "su",
    "su") {

    /**
     * 检查这个 binary 能不能执行，以及执行的结果是什么
     * @param rootBinaryFile 与 root 有关的二进制文件句柄
     * @return 如果能执行，执行的结果符合 root，那么返回中间采集的证据，如果都不满足返回空的 List
     */
    override fun detectBinaryExecutionEvidences(rootBinaryFile: File): List<DetectionEvidence> {
        val evidences: MutableList<DetectionEvidence> = ArrayList()
        if (rootBinaryFile.canExecute()) {
            evidences.add(DetectionEvidence(
                    "SU_EXECUTION",
                rootBinaryFile.absolutePath + " can execute",
                "发现可执行的 su 文件"
            ))
            val executeSuResult: String? = executeBinary()
            if (executeSuResult != null) {
                evidences.add(DetectionEvidence(
                    "SU_EXECUTED",
                    executeSuResult,
                    "执行 su -c id 后 $executeSuResult"
                ));
            }
        }
        return evidences
    }

    /**
     * 执行 su -c id 看看能不能得到类似于
     * uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0 的结果
     * @return 如果能正常执行就返回得到的结果，否则返回 null
     */
    override fun executeBinary(): String? {
        try {
            val process: Process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                BufferedReader(InputStreamReader(process.errorStream)).use { errorReader ->
                    // 如果用户拒绝了权限，那么 result 就应该是 null，error 是 Permission denied
                    // 如果用户允许了，那么 result 就应该是 uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0
                    // error 是 null
                    val result: String? = reader.readLine()
                    if (result != null) {
                        val resultSplit: List<String> = result.split("\\s+")
                        if (resultSplit[0].contains("root") || resultSplit[0].contains("uid=0") ||
                            resultSplit[1].contains("root") || resultSplit[1].contains("gid=0") ||
                            resultSplit[2].contains("root") || resultSplit[2].contains("groups=0")) {
                            return result
                        }
                    }

                    val error: String? = errorReader.readLine()
                    // 这个时候肯定是告诉我们说权限不允许，因为这个文件一定存在（执行这个函数前就找出了文件的位置）
                    // 那么权限不允许说明什么叫不必多说了吧
                    if (error != null) {
                        return error
                    }

                    // 按道理来说是执行不到这里的，这两个不可能都是 null
                    return "command out: $result, error message: $error"
                }
            }
        }
        catch (e: IOException) {
            Log.e(TAG, "An exception threw in SuDetector.executeBinary()", e)
            return null
        }
    }

    companion object {
        private const val TAG: String = "SuDetector";
    }
}
