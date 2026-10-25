package com.guozilu.droidprobe.device

import android.content.Context
import com.guozilu.droidprobe.core.AbstractDetector
import com.guozilu.droidprobe.core.DetectionCategory
import com.guozilu.droidprobe.core.DetectionResult
import com.guozilu.droidprobe.core.DetectionStatus
import com.guozilu.droidprobe.core.RiskLevel

class EmulatorDetector : AbstractDetector(
    "emulator",
    DetectionCategory.DEVICE) {

    override fun doDetect(context: Context?): DetectionResult {
        return DetectionResult(id, category, DetectionStatus.NOT_SUPPORTED, RiskLevel.UNKNOWN, null)
    }

    companion object {
        private const val TAG: String = "EmulatorDetector"
    }
}
