package com.guozilu.droidprobe.core

import android.content.Context

interface Detector {
    val id: String

    val category: DetectionCategory

    fun detect(context: Context?): DetectionResult
}
