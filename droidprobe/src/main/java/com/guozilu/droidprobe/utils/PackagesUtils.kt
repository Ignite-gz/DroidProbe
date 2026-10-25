package com.guozilu.droidprobe.utils;

import android.content.pm.PackageManager;

/**
 * 用于包管理有关的工具类
 */
public class PackagesUtils {
    /**
     * 查询某个包是否被安装了
     * @param packageManager 包管理器
     * @param packageName 要查询的是否被安装了的包名
     * @return 如果被安装了就返回 true，否则返回 false
     */
    public static boolean isPackageInstalled(PackageManager packageManager, String packageName) {
        try {
            packageManager.getPackageInfo(packageName, 0);
            return true;
        }
        catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }
}
