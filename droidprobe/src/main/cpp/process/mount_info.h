//
// Created by ignite on 9/23/26.
//

#ifndef DROIDPROBE_MOUNT_INFO_H
#define DROIDPROBE_MOUNT_INFO_H

#include <string>
#include <vector>

namespace DroidProbe {
    struct MountInfo {
        std::string mount_point;        // 挂载目标路径，如 /system、/data
        std::string mount_options;      // 挂载点级别的选项，如 rw,nosuid,nodev,noexec,relatime
        std::string filesystem_type;    // 文件系统类型（如 ext4, f2fs, tmpfs, overlay, sysfs 等）
        std::string mount_source;       // 挂载源/设备名（如磁盘设备 /dev/block/dm-0 或虚拟设备名）
        std::string super_options;      // 文件系统（Superblock）级别的选项（特定于该文件系统的参数）
    };

    bool get_mounts(std::vector<MountInfo>& mounts);
}

#endif //DROIDPROBE_MOUNT_INFO_H
