package com.guozilu.droidprobe.utils

class MountInfo(
     val mountPoint: String,
     val mountOptions: String,
     val filesystemType: String,
     val mountSource: String,
     val superOptions: String) {

    override fun toString(): String {
        return "MountInfo{mountPoint='$mountPoint'" +
                ", mountOptions='$mountOptions'" +
                ", filesystemType='$filesystemType'" +
                ", mountSource='$mountSource'" +
                ", superOptions='$superOptions'}"
    }
}
