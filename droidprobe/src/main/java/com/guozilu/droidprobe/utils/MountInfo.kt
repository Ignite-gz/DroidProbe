package com.guozilu.droidprobe.utils;

import androidx.annotation.NonNull;

public final class MountInfo {
    private final String mountPoint;
    private final String mountOptions;
    private final String filesystemType;
    private final String mountSource;
    private final String superOptions;

    public MountInfo(
        String mountPoint,
        String mountOptions,
        String filesystemType,
        String mountSource,
        String superOptions
    ) {
        this.mountPoint = mountPoint;
        this.mountOptions = mountOptions;
        this.filesystemType = filesystemType;
        this.mountSource = mountSource;
        this.superOptions = superOptions;
    }

    public String getMountPoint() {
        return mountPoint;
    }

    public String getMountOptions() {
        return mountOptions;
    }

    public String getFilesystemType() {
        return filesystemType;
    }

    public String getMountSource() {
        return mountSource;
    }

    public String getSuperOptions() {
        return superOptions;
    }

    @NonNull
    @Override
    public String toString() {
        return "MountInfo{" +
            "mountPoint='" + mountPoint + '\'' +
            ", mountOptions='" + mountOptions + '\'' +
            ", filesystemType='" + filesystemType + '\'' +
            ", mountSource='" + mountSource + '\'' +
            ", superOptions='" + superOptions + '\'' +
            '}';
    }
}
