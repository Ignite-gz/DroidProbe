package com.guozilu.droidprobe.utils

object ProcessIdentityUtils {
    init {
        System.loadLibrary("droidprobe")
    }

    // 获取 uid
    external fun getUid(): Int

    // 获取 euid
    external fun getEuid(): Int

    // 获取 gid
    external fun getGid(): Int

    // 获取 egid
    external fun getEgid(): Int

    // 获取 groups
    external fun getGroups(): IntArray?
}
