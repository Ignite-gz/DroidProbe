package com.guozilu.droidprobe.utils;

public final class ProcessIdentityUtils {
    static {
        System.loadLibrary("droidprobe");
    }

    // 获取 uid
    public static native int getUid();

    // 获取 euid
    public static native int getEuid();

    // 获取 gid
    public static native int getGid();

    // 获取 egid
    public static native int getEgid();

    // 获取 groups
    public static native int[] getGroups();
}
