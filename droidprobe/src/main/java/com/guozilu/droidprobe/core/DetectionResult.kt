package com.guozilu.droidprobe.core

class DetectionResult(
    val name: String,
    val category: DetectionCategory,
    val status: DetectionStatus,
    val riskLevel: RiskLevel,
    val evidences: List<DetectionEvidence?>?) {

    override fun toString(): String {
        return "DetectionResult{name='$name'" +
                ", category=$category" +
                ", status=$status" +
                ", riskLevel=$riskLevel" +
                ", evidence=$evidences}"
    }

    companion object {
        private const val TAG: String = "DetectionResult"
    }
}
