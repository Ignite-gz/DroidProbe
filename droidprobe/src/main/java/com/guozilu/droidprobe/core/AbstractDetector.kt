package com.guozilu.droidprobe.core;

import android.content.Context;
import android.util.Log;

import java.util.Collections;

/**
 * 一个抽象类，实现了 Detector 接口，继承该类时，应该实现 doDetect 方法以进行检测功能
 */
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

    /**
     * 最核心的检测函数部分应该在这里实现
     * @param context Context 上下文
     * @return DetectionResult 检测结果
     */
    protected abstract DetectionResult doDetect(Context context);

    /**
     * 检测过程中发生了异常，具体就是打印一串异常日志，然后返回发生错误时应该返回的检测结果
     * @param throwable 发生的异常
     * @return 发生异常时应该得到的 DetectionResult 检测结果
     */
    private DetectionResult createErrorResult(Throwable throwable) {
        Log.e(TAG, "A throwable was caught in AbstractDetector.detect()", throwable);
        return new DetectionResult(getId(), getCategory(), DetectionStatus.ERROR,
            RiskLevel.UNKNOWN, Collections.emptyList());
    }
}
