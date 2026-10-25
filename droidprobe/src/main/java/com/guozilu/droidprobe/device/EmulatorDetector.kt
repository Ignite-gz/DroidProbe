package com.guozilu.droidprobe.device;

import android.content.Context;

import com.guozilu.droidprobe.core.AbstractDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionResult;

public final class EmulatorDetector extends AbstractDetector {
    public EmulatorDetector() {
        super("emulator", DetectionCategory.DEVICE);
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        return null;
    }
}
