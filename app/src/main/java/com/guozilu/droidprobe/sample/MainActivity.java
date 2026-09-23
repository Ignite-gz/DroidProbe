package com.guozilu.droidprobe.sample;

import android.os.Bundle;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.guozilu.droidprobe.DroidProbe;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        DroidProbe droidProbe = new DroidProbe();
        Log.i(TAG, droidProbe.scan(this).toString());
    }
}
