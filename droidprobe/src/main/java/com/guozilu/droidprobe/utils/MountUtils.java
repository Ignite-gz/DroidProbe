package com.guozilu.droidprobe.utils;

import java.util.Arrays;
import java.util.List;

public final class MountUtils {
    static {
        System.loadLibrary("droidprobe");
    }

    private static native MountInfo[] getMountsNative();

    public static List<MountInfo> getMounts() {
        MountInfo[] mounts = getMountsNative();

        if (mounts == null) {
            return null;
        }

        return Arrays.asList(mounts);
    }
}
