package com.guozilu.droidprobe.utils;

import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class MountUtils {
    private static final String TAG = "MountUtils";

    static {
        System.loadLibrary("droidprobe");
    }

    public static List<MountInfo> getMounts() {
        MountInfo[] mounts = getMountsNative();

        if (mounts == null) {
            return null;
        }

        return Arrays.asList(mounts);
    }

    /**
     * 依次读取 /proc/self/mountinfo，/proc/self/mounts 或者命令 mount 的输出结果，
     * 有一个能够读取成功就不会读取其它的内容，读取到的每一行都会被解析为一个 MountInfo 对象，
     * 最终组成 MountInfo[] 对象
     * @return 如果读取成功，那么返回对应的 MountInfo[]，否则返回 null
     */
    private static native MountInfo[] getMountsNative();

    /**
     * 读取 /proc/self/mounts 文件，将文件的每一行解析为一个 String 对象，最终组成 String[] 对象
     * @return 读取成功，那么返回对应的 String[]，否则返回 null
     */
    public static native String[] readMounts();

    /**
     * 读取 /proc/self/mountinfo 文件，将文件的每一行解析为一个 String 对象，最终组成 String[] 对象
     * @return 读取成功，那么返回对应的 String[]，否则返回 null
     */
    public static native String[] readMountinfo();

    /**
     * 读取 mount 命令的输出结果，将输出内容的每一行解析为一个 String 对象，最终组成 String[] 对象
     * @return 读取成功，那么返回对应的 String[] 对象，否则返回 null
     */
    public native static String[] readMountCommandLine();
}
