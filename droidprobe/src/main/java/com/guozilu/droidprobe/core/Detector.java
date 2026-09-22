package com.guozilu.droidprobe.core;

import android.content.Context;

import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionResult;

public interface Detector {

    String getId();

    DetectionCategory getCategory();

    DetectionResult detect(Context context);
}
