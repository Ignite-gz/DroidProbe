package com.guozilu.droidprobe.root;

import android.content.Context;
import android.util.Log;

import com.guozilu.droidprobe.core.AbstractDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionEvidence;
import com.guozilu.droidprobe.core.DetectionResult;
import com.guozilu.droidprobe.core.DetectionStatus;
import com.guozilu.droidprobe.core.RiskLevel;
import com.guozilu.droidprobe.utils.MountInfo;
import com.guozilu.droidprobe.utils.MountUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * 检查本来应该只读的系统目录，当前是不是以 rw（read-write）方式挂载
 * 如果有写的权限就说明系统已 root
 * 这里的具体实现细节大概就是读取 /proc/self/mountinfo
 * /proc/self/mounts
 * 执行 mount 命令查看内容，然后把每行的内容解析为一个 MountInfo 对象
 * 检查挂载的 mount point，mount options，FileSystem type，mount source，super options 是否异常
 */
public final class MountDetector extends AbstractDetector {
    private static final String TAG = "MountDetector";

    /**
     * 提前预设的只读目录，一般情况下这些目录是不可能有写的权限的
     */
    private static final String[] SYSTEM_MOUNT_POINTS_TO_CHECK_PATHS = {
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
    };

    public MountDetector() {
        super("mount", DetectionCategory.ROOT);
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        List<DetectionEvidence> evidences = new ArrayList<>();

        List<MountInfo> mountInfos = MountUtils.getMounts();
        if (mountInfos == null) {
            evidences.add(new DetectionEvidence(
                "MOUNT_INFO",
                "/proc/self/mountinfo;/proc/self/mounts;mount",
                "无法获取当前进程的挂载信息"
            ));
            return new DetectionResult(
                getId(),
                getCategory(),
                DetectionStatus.UNKNOWN,
                RiskLevel.LOW,  // 正常来说肯定是可以获取到，获取不到是比较奇怪的一件事
                evidences
            );
        }

        for (MountInfo mountInfo : mountInfos) {
            // 检查系统关键目录的 mount options 是否异常
            if (isSystemMountPointsToCheckPath(mountInfo.getMountPoint())) {
                if (containsOption(mountInfo.getMountOptions(), "rw")) {
                    evidences.add(new DetectionEvidence(
                        "MOUNT_OPTION",
                        mountInfo.getMountPoint(),
                        "关键系统目录以 rw 方式挂载"
                    ));
                }
            }

            // 检查 FileSystem type 是否异常
            if ("overlay".equalsIgnoreCase(mountInfo.getFilesystemType())) {
                evidences.add(new DetectionEvidence(
                    "OVERLAYFS",
                    mountInfo.getFilesystemType(),
                    "关键系统目录使用 overlay 文件系统"
                ));
            }

            // 检查 mount source 是否异常
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
        if (!evidences.isEmpty()) {
            return new DetectionResult(
                getId(),
                getCategory(),
                DetectionStatus.DETECTED,
                RiskLevel.HIGH,
                evidences
            );
        }
        return new DetectionResult(
            getId(),
            getCategory(),
            DetectionStatus.NOT_DETECTED,
            RiskLevel.NONE,
            evidences
        );
    }

    /**
     * 判断挂载路径是否在提前预设好的、指定好的路径中，这些预设的路径，正常情况下一定是只读的，不可能有写的权限
     * @param mountPoint 需要判断的挂载路径
     * @return 如果在就返回 true，否则返回 false
     */
    private static boolean isSystemMountPointsToCheckPath(String mountPoint) {
        for (String path : SYSTEM_MOUNT_POINTS_TO_CHECK_PATHS) {
            if (path.equals(mountPoint)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 判断 target 在不在挂载选项 options 中，挂载选项大概像 ro,seclabel,relatime 这个样子
     * @param options 挂载选项
     * @param target 需要检测在不在 options 中的一个 option
     * @return 如果 target 在 options 中返回 true，否则返回 false
     */
    private static boolean containsOption(String options, String target) {
        if (options == null || target == null) {
            return false;
        }

        for (String option : options.split(",")) {
            if (target.equalsIgnoreCase(option.trim())) {
                return true;
            }
        }

        return false;
    }
}
