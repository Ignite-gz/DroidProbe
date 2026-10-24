package com.guozilu.droidprobe.core

import android.content.Context

interface Detector {

    fun getId(): String

    fun getCategory(): DetectionCategory

    fun detect(context: Context?): DetectionResult?
}
