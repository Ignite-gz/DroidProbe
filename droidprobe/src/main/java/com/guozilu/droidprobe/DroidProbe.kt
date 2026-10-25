package com.guozilu.droidprobe

import android.content.Context
import com.guozilu.droidprobe.core.DetectionResult
import com.guozilu.droidprobe.core.EnvironmentReport
import com.guozilu.droidprobe.root.RootDetector

class DroidProbe {
    fun scan(context: Context): EnvironmentReport {
        val applicationContext: Context = context.applicationContext
        val results: MutableList<DetectionResult> = ArrayList()

        // 后面在这里调用各种 Detector
        results.add(RootDetector().detect(applicationContext))
        // results.add(DeviceDetector().detect(applicationContext))
        // results.add(RuntimeDetector().detect(applicationContext))

        return EnvironmentReport(System.currentTimeMillis(), results)
    }
}
