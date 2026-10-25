package com.guozilu.droidprobe.utils

import android.util.Log
import java.io.IOException

object SystemPropertiesUtils {
    private const val TAG: String = "SystemPropertiesUtils"

    init {
        System.loadLibrary("droidprobe")
    }

    /**
     * 类似于 adb shell getprop key 得到的值
     * 本来想用 Runtime.getRuntime().exec(new String[]{"getprop", key}) 来写的
     * 但是发现当 key 为 ro.debuggable 时有 bug，我暂时排查不出来，所以保险起见用了 __system_property_get
     * @param key 要获取的属性
     * @return 获取到的属性
     */
    external fun getprop(key: String): String?

    fun getprop(): String? {
        try {
            val process: Process = Runtime.getRuntime().exec(arrayOf("getprop"))
            return process.inputStream.bufferedReader().use { bufferedReader ->
                bufferedReader.readText()
            }
        }
        catch (e: IOException) {
            Log.e(TAG, "An exception threw in SystemPropertiesUtils.getprop()", e)
            return null
        }
    }
}
