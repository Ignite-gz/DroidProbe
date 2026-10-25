package com.guozilu.droidprobe.core;

import androidx.annotation.NonNull;

public final class DetectionEvidence {
    private final String type;
    private final String value;
    private final String description;

    public DetectionEvidence(String type, String value, String description) {
        this.type = type;
        this.value = value;
        this.description = description;
    }

    public String getType() {
        return type;
    }

    public String getValue() {
        return value;
    }

    public String getDescription() {
        return description;
    }

    @NonNull
    @Override
    public String toString() {
        return "DetectionEvidence{" +
            "type='" + type + '\'' +
            ", value='" + value + '\'' +
            ", description='" + description + '\'' +
            '}';
    }
}
