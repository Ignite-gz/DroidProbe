package com.guozilu.droidprobe.root

import android.content.Context
import android.util.Log
import com.guozilu.droidprobe.core.CompositeDetector
import com.guozilu.droidprobe.core.DetectionCategory
import com.guozilu.droidprobe.core.DetectionResult
import com.guozilu.droidprobe.core.DetectionStatus
import com.guozilu.droidprobe.core.Detector
import com.guozilu.droidprobe.core.RiskLevel

class RootDetector : CompositeDetector("root",
    DetectionCategory.ROOT,
    listOf<Detector>(
        RootAppDetector(),
        PotentiallyRiskyAppDetector(),
        SuDetector(),
        SystemPropertyDetector(),
        MountDetector(),
        MagiskDetector(),
        ProcessIdentityDetector(),
        BusyBoxDetector(),
        KernelSuDetector(),
        APatchDetector())) {

    override fun doDetect(context: Context?): DetectionResult {
        val results: List<DetectionResult> = detectChildren(context)

        // 聚合 Root 结果
        results.forEach { result ->
            Log.i(TAG, result.toString());
        }

        // 先看看能不能正常运行，再考虑返回结果该怎么设计
        return DetectionResult("root_detector", DetectionCategory.ROOT, DetectionStatus.UNKNOWN,
            RiskLevel.UNKNOWN, mutableListOf());
    }

    companion object {
        private const val TAG: String = "RootDetector"
    }
}
