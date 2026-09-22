package com.guozilu.droidprobe.root;

import android.content.Context;

import com.guozilu.droidprobe.core.AbstractDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionResult;

public class RootAppDetector extends AbstractDetector {
    public RootAppDetector() {
        super("root_app", DetectionCategory.ROOT);
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        // 等下再实现
        return null;
    }
}
