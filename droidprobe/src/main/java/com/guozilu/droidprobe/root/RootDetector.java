package com.guozilu.droidprobe.root;

import android.content.Context;
import android.util.Log;

import com.guozilu.droidprobe.core.CompositeDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionResult;

import java.util.Arrays;
import java.util.List;

public class RootDetector extends CompositeDetector {
    private static final String TAG = "RootDetector";

    public RootDetector() {
        super("root", DetectionCategory.ROOT, Arrays.asList(
            new RootAppDetector(),
            new PotentiallyRiskyAppDetector(),
            new SuDetector(),
            new SystemPropertyDetector(),
            new MountDetector()
        ));
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        List<DetectionResult> results = detectChildren(context);

        // 聚合 Root 结果
        for (DetectionResult result : results) {
            Log.i(TAG, result.toString());
        }

        // 先看看能不能正常运行，再考虑返回结果该怎么设计
        return null;
    }
}
