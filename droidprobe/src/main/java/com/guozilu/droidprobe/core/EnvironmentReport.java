package com.guozilu.droidprobe.core;

import android.os.Build;

import androidx.annotation.NonNull;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class EnvironmentReport {
    private final long timestamp;
    private final List<DetectionResult> results;

    public EnvironmentReport(long timestamp, List<DetectionResult> results) {
        this.timestamp = timestamp;
        this.results = Collections.unmodifiableList(results);
    }

    public long getTimestamp() {
        return timestamp;
    }

    public List<DetectionResult> getResults() {
        return results;
    }

    public List<DetectionResult> getDetectedResults() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            return results.stream()
                .filter(result -> result.getStatus() == DetectionStatus.DETECTED)
                .collect(Collectors.toList());
        }
        else {
            List<DetectionResult> retval = new ArrayList<>();
            for (DetectionResult result : results) {
                if (result.getStatus() == DetectionStatus.DETECTED) {
                    retval.add(result);
                }
            }
            return retval;
        }
    }

    public List<DetectionResult> getResults(DetectionCategory category) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            return results.stream()
                .filter(result -> result.getCategory() == category)
                .collect(Collectors.toList());
        }
        else {
            List<DetectionResult> retval = new ArrayList<>();
            for (DetectionResult result : results) {
                if (result.getCategory() == category) {
                    retval.add(result);
                }
            }
            return retval;
        }
    }

    @NonNull
    @Override
    public String toString() {
        return "EnvironmentReport{" +
            "timestamp=" + timestamp +
            ", results=" + results +
            '}';
    }
}
