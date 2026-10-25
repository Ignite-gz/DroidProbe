package com.guozilu.droidprobe.root

import android.content.Context
import com.guozilu.droidprobe.core.AbstractDetector
import com.guozilu.droidprobe.core.DetectionCategory
import com.guozilu.droidprobe.core.DetectionEvidence
import com.guozilu.droidprobe.core.DetectionResult
import com.guozilu.droidprobe.core.DetectionStatus
import com.guozilu.droidprobe.core.RiskLevel
import com.guozilu.droidprobe.utils.MountInfo
import com.guozilu.droidprobe.utils.MountUtils

/**
 * 检查本来应该只读的系统目录，当前是不是以 rw（read-write）方式挂载
 * 如果有写的权限就说明系统已 root
 * 这里的具体实现细节大概就是读取 /proc/self/mountinfo
 * /proc/self/mounts
 * 执行 mount 命令查看内容，然后把每行的内容解析为一个 MountInfo 对象
 * 检查挂载的 mount point，mount options，FileSystem type，mount source，super options 是否异常
 */
class MountDetector : AbstractDetector(
    "mount",
    DetectionCategory.ROOT) {

    override fun doDetect(context: Context?): DetectionResult {
        val evidences: MutableList<DetectionEvidence> = ArrayList()

        val mountInfos: List<MountInfo>? = MountUtils.getMounts()
        if (mountInfos == null) {
            evidences.add(DetectionEvidence(
                "MOUNT_INFO",
                "/proc/self/mountinfo;/proc/self/mounts;mount",
                "无法获取当前进程的挂载信息"
            ))
            return DetectionResult(
                id,
                category,
                DetectionStatus.UNKNOWN,
                RiskLevel.LOW,  // 正常来说肯定是可以获取到，获取不到是比较奇怪的一件事
                evidences
            )
        }

        for (mountInfo: MountInfo in mountInfos) {
            // Log.i(TAG, mountInfo.toString())
            // 检查系统关键目录的 mount options 是否异常
            if (isSystemMountPointsToCheckPath(mountInfo.mountPoint)) {
                if (containsOption(mountInfo.mountOptions, "rw")) {
                    evidences.add(DetectionEvidence(
                        "MOUNT_OPTION",
                        mountInfo.mountPoint,
                        "关键系统目录以 rw 方式挂载"
                    ))
                }
            }

            // 检查 FileSystem type 是否异常
            if ("overlay".equals(mountInfo.filesystemType, true)) {
                evidences.add(DetectionEvidence(
                    "OVERLAYFS",
                    mountInfo.filesystemType,
                    "关键系统目录使用 overlay 文件系统"
                ))
            }
        }
        if (!evidences.isEmpty()) {
            return DetectionResult(
                id,
                category,
                DetectionStatus.DETECTED,
                RiskLevel.HIGH,
                evidences
            )
        }
        return DetectionResult(
            id,
            category,
            DetectionStatus.NOT_DETECTED,
            RiskLevel.NONE,
            evidences
        )
    }

    companion object {
        private const val TAG = "MountDetector"

        /**
         * 提前预设的目录，一般情况下这些目录是不可能有写的权限的
         */
        private val SYSTEM_MOUNT_POINTS_TO_CHECK_PATHS: Array<String> = arrayOf(
            "/system",
            "/system/bin",
            "/system/sbin",
            "/system/xbin",
            "/system_ext",
            "/vendor",
            "/vendor/bin",
            "/product",
            "/odm",
            "/sbin",
            "/etc"
        )

        /**
         * 判断挂载路径是否在提前预设好的、指定好的路径中，这些预设的路径，正常情况下一定不可能有写的权限
         * @param mountPoint 需要判断的挂载路径
         * @return 如果在就返回 true，否则返回 false
         */
        private fun isSystemMountPointsToCheckPath(mountPoint: String): Boolean {
            for (path: String in SYSTEM_MOUNT_POINTS_TO_CHECK_PATHS) {
                if (path == mountPoint) {
                    return true
                }
            }

            return false
        }

        /**
         * 判断 target 在不在挂载选项 options 中，挂载选项的内容大概像 ro,seclabel,relatime 这个样子
         * @param options 挂载选项
         * @param target 需要检测在不在 options 中的一个 option
         * @return 如果 target 在 options 中返回 true，否则返回 false
         */
        private fun containsOption(options: String?, target: String?): Boolean {
            if (options == null || target == null) {
                return false
            }

            for (option: String in options.split(",")) {
                if (target.equals(option.trim(), true)) {
                    return true
                }
            }

            return false
        }
    }
}
