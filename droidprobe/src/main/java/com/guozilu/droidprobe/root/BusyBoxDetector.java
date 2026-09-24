package com.guozilu.droidprobe.root;

import android.content.Context;

import com.guozilu.droidprobe.core.AbstractDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionResult;

/**
 * 这个类的检测功能其实和检测 magisk 是类似的
 * 都是在检查 busybox 二进制以及 which busybox
 * 所以这个类几乎就是直接复制了 MagiskDetector
 * 但我没有去把这两个类删掉，然后创建一个类似于 BinaryDetector
 * 然后再让 magisk
 */
public final class BusyBoxDetector extends AbstractDetector {
    public BusyBoxDetector() {
        super("busy_box", DetectionCategory.ROOT);
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        return null;
    }
}
