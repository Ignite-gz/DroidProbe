package com.guozilu.droidprobe.core

class DetectionEvidence(
    val type: String,
    val value: String?,
    val description: String?) {

    override fun toString(): String {
        return "DetectionEvidence{type='$type'" +
                ", value='$value'" +
                ", description='$description'}"
    }

    companion object {
        private const val TAG: String = "DetectionEvidence"
    }
}
