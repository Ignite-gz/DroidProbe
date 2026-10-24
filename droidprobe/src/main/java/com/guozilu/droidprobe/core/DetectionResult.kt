package com.guozilu.droidprobe.core

class DetectionResult(
    private val name: String,
    private val category: DetectionCategory,
    private val status: DetectionStatus,
    private val riskLevel: RiskLevel,
    private val evidences: List<DetectionEvidence>) {

    fun getName(): String {
        return name
    }

    fun getCategory(): DetectionCategory {
        return category
    }

    fun getStatus(): DetectionStatus {
        return status
    }

    fun getRiskLevel(): RiskLevel {
        return riskLevel
    }

    fun getEvidences(): List<DetectionEvidence> {
        return evidences
    }

    override fun toString(): String {
        return "DetectionResult{name='$name'" +
                ", category=$category" +
                ", status=$status" +
                ", riskLevel=$riskLevel" +
                ", evidence=$evidences}"
    }
}
