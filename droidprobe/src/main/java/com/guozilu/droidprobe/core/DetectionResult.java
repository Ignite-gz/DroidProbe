package com.guozilu.droidprobe.core;

import androidx.annotation.NonNull;

import java.util.Collections;
import java.util.List;

public final class DetectionResult {
    private final String name;
    private final DetectionCategory category;
    private final DetectionStatus status;
    private final RiskLevel riskLevel;
    private final List<DetectionEvidence> evidence;

    public DetectionResult(String name, DetectionCategory category, DetectionStatus status,
        RiskLevel riskLevel, List<DetectionEvidence> evidence) {

        this.name = name;
        this.category = category;
        this.status = status;
        this.riskLevel = riskLevel;
        this.evidence =
            evidence == null
            ? Collections.emptyList()
            : Collections.unmodifiableList(evidence);
    }

    public String getName() {
        return name;
    }

    public DetectionCategory getCategory() {
        return category;
    }

    public DetectionStatus getStatus() {
        return status;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public List<DetectionEvidence> getEvidence() {
        return evidence;
    }

    @NonNull
    @Override
    public String toString() {
        return "DetectionResult{" +
            "name='" + name + '\'' +
            ", category=" + category +
            ", status=" + status +
            ", riskLevel=" + riskLevel +
            ", evidence=" + evidence +
            '}';
    }
}
