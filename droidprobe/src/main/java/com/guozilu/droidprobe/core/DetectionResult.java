package com.guozilu.droidprobe.core;

import androidx.annotation.NonNull;

import java.util.Collections;
import java.util.List;

public final class DetectionResult {
    private final String name;
    private final DetectionCategory category;
    private final DetectionStatus status;
    private final RiskLevel riskLevel;
    private final List<DetectionEvidence> evidences;

    public DetectionResult(String name, DetectionCategory category, DetectionStatus status,
        RiskLevel riskLevel, List<DetectionEvidence> evidences) {

        this.name = name;
        this.category = category;
        this.status = status;
        this.riskLevel = riskLevel;
        this.evidences =
            evidences == null
            ? Collections.emptyList()
            : Collections.unmodifiableList(evidences);
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

    public List<DetectionEvidence> getEvidences() {
        return evidences;
    }

    @NonNull
    @Override
    public String toString() {
        return "DetectionResult{" +
            "name='" + name + '\'' +
            ", category=" + category +
            ", status=" + status +
            ", riskLevel=" + riskLevel +
            ", evidence=" + evidences +
            '}';
    }
}
