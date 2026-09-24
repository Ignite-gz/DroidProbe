//
// Created by ignite on 9/24/26.
//

#ifndef DROIDPROBE_PROCESS_IDENTITY_H
#define DROIDPROBE_PROCESS_IDENTITY_H

#include <sys/types.h>
#include <vector>

namespace DroidProbe {
    /**
    * 获取当前进程的 uid
    * @return uid
    */
    uid_t get_process_uid();

    /**
    * 获取当前进程的有效 uid 也就是 euid
    * @return euid
    */
    uid_t get_process_euid();

    /**
    * 获取当前进程所属组的 gid
    * @return gid
    */
    gid_t get_process_gid();

    /**
    * 获取当前进程所属组的有效 gid 也就是 egid
    * @return egid
    */
    gid_t get_process_egid();

    /**
    * 获取当前进程所有的补充组
    * @return 这些补充组的 gid
    */
    std::vector<gid_t> get_process_groups();
}

#endif //DROIDPROBE_PROCESS_IDENTITY_H
