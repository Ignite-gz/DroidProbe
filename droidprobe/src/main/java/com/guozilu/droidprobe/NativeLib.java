package com.guozilu.droidprobe;

public class NativeLib {

    // Used to load the 'droidprobe' library on application startup.
    static {
        System.loadLibrary("droidprobe");
    }

    /**
     * A native method that is implemented by the 'droidprobe' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}