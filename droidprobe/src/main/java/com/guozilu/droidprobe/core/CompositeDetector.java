package com.guozilu.droidprobe.core;

import android.content.Context;

import java.util.ArrayList;
import java.util.List;

public abstract class CompositeDetector extends AbstractDetector {
    private final List<Detector> detectors;

    protected CompositeDetector(String id, DetectionCategory category, List<Detector> detectors) {
        super(id, category);
        this.detectors = detectors;
    }

    protected final List<DetectionResult> detectChildren(Context context) {
        List<DetectionResult> results = new ArrayList<>();
        for (Detector detector : detectors) {
            results.add(detector.detect(context));
        }
        return results;
    }
}
