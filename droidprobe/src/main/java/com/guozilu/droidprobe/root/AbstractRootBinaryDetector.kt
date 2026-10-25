package com.guozilu.droidprobe.root

import android.content.Context
import android.util.Log
import com.guozilu.droidprobe.core.AbstractDetector
import com.guozilu.droidprobe.core.DetectionCategory
import com.guozilu.droidprobe.core.DetectionEvidence
import com.guozilu.droidprobe.core.DetectionResult
import com.guozilu.droidprobe.core.DetectionStatus
import com.guozilu.droidprobe.core.RiskLevel
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.util.Collections

/**
 * 这是一个抽象类，传入 rootBinaryName 就能完成全部操作
 * 这个类用来检查二进制文件是否存在
 * 在常见的路径和环境变量的路径中查找它们
 * 以及 which rootBinaryName 是否能找到文件
 * 这个类还可以在找到路径的时候，检查可执行情况，只需调用者 override detectBinaryExecutionEvidences 即可
 * 它还可以执行这个文件并且将文件执行的输出结果加入到最终 doDetect() 的返回结果的 List 中，
 * 也只需调用者 override executeBinary 即可
 */
abstract class AbstractRootBinaryDetector(
    id: String,
    private val rootBinaryName: String
) : AbstractDetector(id, DetectionCategory.ROOT) {

    override fun doDetect(context: Context?): DetectionResult {
        val evidences: MutableList<DetectionEvidence> = ArrayList()
        // 查找常见路径以及环境变量看看有没有 rootBinaryName 文件
        for (path: String in /* KNOWN_COMMON_PATHS */ getAllPaths()) {
            val tmpPath = path + rootBinaryName
            evidences.addAll(detectBinaryPathEvidences(tmpPath))
        }

        // 查看 which rootBinaryName 的结果
        // Log.e(TAG, "[" + getWhichBinaryResult() + "]")
        val whichBinary: String? = getWhichBinaryResult()
        if (whichBinary != null) {
            evidences.add(DetectionEvidence(
                "WHICH_" + rootBinaryName.uppercase(),
                whichBinary,
                "执行 which $rootBinaryName 发现 $rootBinaryName 文件"
            ))
            val file: File = File(whichBinary)
            evidences.addAll(detectBinaryExecutionEvidences(file))
        }

        // 进行其他补充的检测
        evidences.addAll(detectOthers());

        if (evidences.isEmpty()) {
            return DetectionResult(
                id,
                category,
                DetectionStatus.NOT_DETECTED,
                RiskLevel.NONE,
                evidences
            )
        }
        return DetectionResult(
            id,
            category,
            DetectionStatus.DETECTED,
            RiskLevel.HIGH,
            evidences
        )
    }

    /**
     * which rootBinaryName 的结果
     * @return 如果命令执行成功，那么返回命令输出的内容，否则返回 null
     */
    private fun getWhichBinaryResult(): String? {
        try {
            val process: Process = Runtime.getRuntime().exec(arrayOf("which", rootBinaryName))
            BufferedReader(InputStreamReader(process.inputStream)).use {
                reader -> return reader.readLine()
            }
        }
        catch (e: IOException) {
            Log.e(TAG, "An exception was caught in AbstractRootBinaryDetector.getWhichBinaryResult()", e)
            return null
        }
    }

    /**
     * 检查指定 binary 路径的文件是否存在，是否可执行，是否真的能直接身份变为 root
     * @param path 指定 binary 的路径
     * @return 结果成立时的证据，如果都不成立则返回空的 List
     */
    private fun detectBinaryPathEvidences(path: String): List<DetectionEvidence> {
        val evidences: MutableList<DetectionEvidence> = ArrayList()
        val file: File = File(path)
        if (file.exists()) {
            evidences.add(DetectionEvidence(
                file.getName().uppercase() + "_PATH",
                path,
                "发现 " + file.getName() + " 文件"
            ))

            evidences.addAll(detectBinaryExecutionEvidences(file))
        }
        return evidences
    }

    /**
     * 这个方法在这里是一个 stub
     * 如果想去获取一下这个二进制文件执行的证据，那么需要 override 这个方法，否则不需要做任何操作
     * 约定是，rootBinaryFile 是一个 与 root 有关的二进制文件的 File 的句柄，打开了这个要执行的二进制文件
     * 如果能执行，那么返回相应的 List&ltDetectionEvidence&gt，如果不能执行返回空序列
     * @param rootBinaryFile 要查看执行情况的二进制文件的句柄
     * @return 如果能执行则返回文件执行时的证据列表，否则返回空列表
     */
    protected open fun detectBinaryExecutionEvidences(rootBinaryFile: File): List<DetectionEvidence>
        = Collections.emptyList()

    /**
     * 这个方法在这里是一个 stub
     * 你可以在这里在类似于命令行运行可执行文件，然后返回可执行文件运行之后的输出结果
     * @return 如果可执行文件正常运行，返回它的输出内容，否则返回 null
     */
    protected open fun executeBinary(): String? = null

    /**
     * 这个方法在这里是一个 stub
     * 继承这个抽象类的类，可能需要这个抽象类预定好的功能外的其他功能
     * 但需求不同，不可能涵盖所有，所以这个方法用于给派生类实现其他查找功能
     * @return 检查时所产生的证据(List&ltDetectionEvidence&gt)
     */
    protected open fun detectOthers(): List<DetectionEvidence> = Collections.emptyList()

    companion object {
        private const val TAG: String = "AbstractRootBinaryDetector"

        // 这些是可能的静态路径
        // 那肯定考虑到不同系统不同 root 方式不一样，但是肯定是加入了环境变量的，所以应该把环境变量也加入进去
        private val KNOWN_COMMON_PATHS: Array<String> = arrayOf(
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
        )

        /**
         * 获取这些提前定义路径加上环境变量的全部路径
         * @return 返回这些路径
         */
        private fun getAllPaths(): List<String> {
            val paths: MutableList<String> = mutableListOf(*KNOWN_COMMON_PATHS)
            // Log.i(TAG, Objects.requireNonNull(System.getenv("PATH")))
            // 拆解一下
            // 因为不同手机的可执行文件的目录是有差别的，KNOWN_COMMON_PATHS 只是涵盖一些普通情况和一些极端情况
            // 读取系统的 PATH 才能真正知道所有的可执行目录在哪
            val systemPaths: String? = System.getenv("PATH")
            if (systemPaths.isNullOrEmpty()) {
                return paths
            }

            for (systemPath: String in systemPaths.split(":")) {
                var systemPathTemp = systemPath
                if (!systemPathTemp.endsWith("/")) {
                    systemPathTemp += "/"
                }
                if (!paths.contains(systemPathTemp)) {
                    paths.add(systemPathTemp)
                }
            }

            return paths
        }
    }
}
