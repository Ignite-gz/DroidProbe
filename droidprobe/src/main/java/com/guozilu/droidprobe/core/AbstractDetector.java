package com.guozilu.droidprobe.core;

import android.content.Context;
import android.util.Log;

import java.util.Collections;

public abstract class AbstractDetector implements Detector {
    private static final String TAG = "AbstractDetector";
    private final String id;
    private final DetectionCategory category;

    protected AbstractDetector(String id, DetectionCategory category) {
        this.id = id;
        this.category = category;
    }

    @Override
    public final String getId() {
        return id;
    }

    @Override
    public final DetectionCategory getCategory() {
        return category;
    }

    @Override
    public final DetectionResult detect(Context context) {
        try {
            return doDetect(context);
        }
        catch (Throwable throwable) {
            return createErrorResult(throwable);
        }
    }

    protected abstract DetectionResult doDetect(Context context);

    // 检测过程中发生了异常
    private DetectionResult createErrorResult(Throwable throwable) {
        Log.e(TAG, "A throwable was caught in AbstractDetector.detect()", throwable);
        return new DetectionResult(getId(), getCategory(), DetectionStatus.ERROR,
            RiskLevel.UNKNOWN, Collections.emptyList());
    }
}
