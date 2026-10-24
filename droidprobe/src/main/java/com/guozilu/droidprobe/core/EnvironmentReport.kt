package com.guozilu.droidprobe.core

import android.os.Build
import java.util.stream.Collectors

class EnvironmentReport(
    private val timestamp: Long,
    private val results: MutableList<DetectionResult>) {

    fun getDetectedResults(): MutableList<DetectionResult> {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            return results.stream()
                .filter { result -> result.getStatus() == DetectionStatus.DETECTED }
                .collect(Collectors.toList())
        }
        else {
            val retval: MutableList<DetectionResult> = ArrayList()
            results.forEach {
                result -> if (result.getStatus() == DetectionStatus.DETECTED) {
                    retval.add(result)
                }
            }
            return retval
        }
    }

    fun getResults(category: DetectionCategory): MutableList<DetectionResult> {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            return results.stream()
                .filter { result -> result.getCategory() == category }
                .collect(Collectors.toList())
        }
        else {
            val retval: MutableList<DetectionResult> = ArrayList()
            results.forEach {
                result ->
                if (result.getCategory() == category) {
                    retval.add(result)
                }
            }
            return retval
        }
    }

    override fun toString(): String {
        return "EnvironmentReport{timestamp=$timestamp, results=$results}"
    }
}
