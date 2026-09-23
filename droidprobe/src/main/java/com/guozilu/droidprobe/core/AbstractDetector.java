package com.guozilu.droidprobe.core;

import android.content.Context;

public abstract class AbstractDetector implements Detector {
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
            // return createErrorResult(throwable);
            throw throwable;
        }
    }

    protected abstract DetectionResult doDetect(Context context);

    // 检测过程中发生了异常
    private DetectionResult createErrorResult(Throwable throwable) {
        return null;    // 暂时不处理这个问题
    }
}
