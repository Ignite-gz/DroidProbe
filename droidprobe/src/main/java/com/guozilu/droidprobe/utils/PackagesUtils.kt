package com.guozilu.droidprobe.utils

import android.content.pm.PackageManager

/**
 * 用于包管理有关的工具类
 */
object PackagesUtils {
    /**
     * 查询某个包是否被安装了
     * @param packageManager 包管理器
     * @param packageName 要查询的是否被安装了的包名
     * @return 如果被安装了就返回 true，否则返回 false
     */
    fun isPackageInstalled(packageManager: PackageManager, packageName: String): Boolean {
        try {
            packageManager.getPackageInfo(packageName, 0);
            return true;
        }
        catch (_: PackageManager.NameNotFoundException) {
            return false;
        }
    }
}
