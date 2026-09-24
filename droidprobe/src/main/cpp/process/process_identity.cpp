//
// Created by ignite on 9/24/26.
//

#include "process_identity.h"

#include <unistd.h>

uid_t DroidProbe::get_process_uid() {
    return getuid();
}

uid_t DroidProbe::get_process_euid() {
    return geteuid();
}

gid_t DroidProbe::get_process_gid() {
    return getgid();
}

gid_t DroidProbe::get_process_egid() {
    return getegid();
}

std::vector<gid_t> DroidProbe::get_process_groups() {
    // 先获取当前进程补充组的数量
    int group_count = getgroups(0, nullptr);
    if (group_count <= 0) {
        return {};
    }

    // 根据补充组的数量分配合适空间的数组
    std::vector<gid_t> groups(group_count);

    // 传入分配好的数组和实际补充组的数量获取 gid 列表
    int result = getgroups(group_count, groups.data());
    if (result < 0) {
        return {};
    }

    groups.resize(result);
    return groups;
}
