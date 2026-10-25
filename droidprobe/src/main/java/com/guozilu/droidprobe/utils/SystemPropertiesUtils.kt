package com.guozilu.droidprobe.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class SystemPropertiesUtils {
    private static final String TAG = "SystemPropertiesUtils";

    static {
        System.loadLibrary("droidprobe");
    }

    /**
     * 类似于 getprop key 得到的值
     * 本来想用 Runtime.getRuntime().exec(new String[]{"getprop", key}) 来写的
     * 但是发现当 key 为 ro.debuggable 时有 bug，我暂时排查不出来，所以保险起见用了 __system_property_get
     * @param key 要获取的属性
     * @return 获取到的属性
     */
    public static native String getprop(String key);

    public static String getprop() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"getprop"});
            try (BufferedReader bufferedReader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
                String line;
                StringBuilder result = new StringBuilder();
                while ((line = bufferedReader.readLine()) != null) {
                    result.append(line).append('\n');
                }
                return result.toString();
            }
        }
        catch (IOException e) {
            return null;
        }
    }
}
