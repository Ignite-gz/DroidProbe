package com.guozilu.droidprobe.root

import android.util.Log
import com.guozilu.droidprobe.core.DetectionEvidence
import com.guozilu.droidprobe.utils.MountUtils
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader

/**
 * 这个类的检测功能其实和检测 su 是类似的
 * 都是在检查 magisk 二进制以及 which magisk
 * 所以这个类就是 SuDetector 的基础上进行了一些改动
 */
class MagiskDetector : AbstractRootBinaryDetector(
    "magisk",
    "magisk") {

    /**
     * 检查这个 binary 能不能执行，以及执行的结果是什么
     * @param rootBinaryFile 与 root 有关的二进制文件句柄
     * @return 如果能执行，执行的结果符合 root，那么返回中间采集的证据，如果都不满足返回空的 List
     */
    override fun detectBinaryExecutionEvidences(rootBinaryFile: File): List<DetectionEvidence>  {
        val evidences: MutableList<DetectionEvidence> = ArrayList()
        if (rootBinaryFile.canExecute()) {
            evidences.add(DetectionEvidence(
                "MAGISK_EXECUTION",
                rootBinaryFile.absolutePath + " can execute",
                "发现可执行的 magisk 文件"
            ))
            val executeSuResult: String? = executeBinary()
            if (executeSuResult != null) {
                evidences.add(DetectionEvidence(
                    "MAGISK_EXECUTED",
                    executeSuResult,
                    "执行 magisk -v 后，得到：$executeSuResult"
                ))
            }
        }
        return evidences
    }

    /**
     * 执行 magisk -v 看看有没有效果，以及有什么效果
     * @return 如果能正常执行就返回得到的结果，否则返回 null
     */
    override fun executeBinary(): String? {
        try {
            val process: Process = Runtime.getRuntime().exec(arrayOf("magisk", "-v"))
            BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                BufferedReader(InputStreamReader(process.errorStream)).use {  errorReader ->
                    val result: String? = reader.readLine()
                    if (result != null) {
                        return result
                    }

                    val error: String? = errorReader.readLine ()
                    if (error != null) {
                        return error
                    }

                    // 按道理来说是执行不到这里的，这两个不可能都是 null
                    return "command out: $result, error message: $error"
                }
            }
        }
        catch (e: IOException) {
            Log.e(TAG, "An exception threw in MagiskDetector.executeBinary()", e)
            return null
        }
    }

    /**
     * 其它补充的检测
     * @return 检查时所产生的证据(List&ltDetectionEvidence&gt)
     */
    override fun detectOthers(): List<DetectionEvidence> {
        // 检查 mount source 是否异常
        val evidences: MutableList<DetectionEvidence> = ArrayList()

        // 检查能否读取到挂载信息
        var mountInfos: Array<String>? = MountUtils.readMountinfo()
        if (mountInfos == null) {
            mountInfos = MountUtils.readMounts()
            if (mountInfos == null) {
                mountInfos = MountUtils.readMountCommandLine()
                if (mountInfos == null) {
                    evidences.add(DetectionEvidence(
                        "MOUNT_INFO",
                        "/proc/self/mountinfo;/proc/self/mounts;mount",
                        "无法获取当前进程的挂载信息"
                    ))
                    return evidences
                }
            }
        }

        // 遍历挂载信息
        for (mountInfo: String in mountInfos) {
            // Log.i(TAG, mountInfo)
            // 检查挂载源和挂载目标路径是否为 magisk
            if (mountInfo.contains("magisk")) {
                evidences.add(DetectionEvidence(
                    "MOUNT_SOURCE",
                    mountInfo,
                    "关键系统目录的挂载源为 magisk"
                ))
            }

            // 检查 magisk 模块挂载
            if (mountInfo.contains("/adb/modules/")) {
                evidences.add(DetectionEvidence(
                    "MOUNT_POINT",
                    mountInfo,
                    "关键系统目录的挂载目标路径为 magisk 模块"
                ))
            }
        }

        return evidences
    }

    companion object {
        private const val TAG: String = "MagiskDetector"
    }
}
