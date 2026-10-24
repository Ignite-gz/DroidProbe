package com.guozilu.droidprobe.core;

import android.content.Context;

import java.util.ArrayList;
import java.util.List;

/**
 * 一个抽象类，继承了 AbstractDetector，用来同时完成多个检测分支
 * 在该构造该类实例时，应该传递这些检测分支，detectChildren() 会调用这些 Detector.detect(context)
 * 应在重写 doDetect() 方法时，在其中调用 detectChildren() 方法来完成对应的逻辑，否则这些子分支的检测，
 * 将不会被执行
 */
public abstract class CompositeDetector extends AbstractDetector {
    private final List<Detector> detectors;

    protected CompositeDetector(String id, DetectionCategory category, List<Detector> detectors) {
        super(id, category);
        this.detectors = detectors;
    }

    /**
     * 遍历 detectors，逐个执行 Detector.detect(context)
     * 将返回结果聚合成一个 List&lt;DetectionResult&gt; results
     * @param context Context context 上下文
     * @return 所有分支的 Detector 的检测结果的聚合
     */
    protected final List<DetectionResult> detectChildren(Context context) {
        List<DetectionResult> results = new ArrayList<>();
        for (Detector detector : detectors) {
            results.add(detector.detect(context));
        }
        return results;
    }
}
