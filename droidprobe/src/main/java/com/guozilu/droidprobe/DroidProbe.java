package com.guozilu.droidprobe;

import android.content.Context;

import com.guozilu.droidprobe.core.DetectionResult;
import com.guozilu.droidprobe.core.EnvironmentReport;
import com.guozilu.droidprobe.root.RootDetector;

import java.util.ArrayList;
import java.util.List;

public class DroidProbe {
    public EnvironmentReport scan(Context context) {
        Context applicationContext = context.getApplicationContext();
        List<DetectionResult> results = new ArrayList<>();

        // 后面在这里调用各种 Detector
        results.add(new RootDetector().detect(applicationContext));
        // results.add(new DeviceDetector().detect(applicationContext));
        // results.add(new RuntimeDetector().detect(applicationContext));

        return new EnvironmentReport(System.currentTimeMillis(), results);
    }
}
