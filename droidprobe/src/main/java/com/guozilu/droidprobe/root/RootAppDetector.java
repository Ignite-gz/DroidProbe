package com.guozilu.droidprobe.root;

import android.content.Context;
import android.content.pm.PackageManager;

import com.guozilu.droidprobe.core.AbstractDetector;
import com.guozilu.droidprobe.core.DetectionCategory;
import com.guozilu.droidprobe.core.DetectionEvidence;
import com.guozilu.droidprobe.core.DetectionResult;
import com.guozilu.droidprobe.core.DetectionStatus;
import com.guozilu.droidprobe.core.RiskLevel;
import com.guozilu.droidprobe.utils.PackagesUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * 检查手机上有没有安装用于管理 root 的软件包名，如 Magisk
 * 发现软件其实也不代表真的 root 了，但这个类就是专门查包名的
 */
public final class RootAppDetector extends AbstractDetector {
    private static final String TAG = "RootAppDetector";

    private static final String[] ROOT_APP_PACKAGES = {
        // Magisk
        "com.topjohnwu.magisk",

        // Magisk Alpha
        "io.github.vvb2060.magisk",

        // Kitsune Mask（狐狸面具）
        "io.github.huskydg.magisk",

        // KernelSU
        "me.weishu.kernelsu",

        // KernelSU Next
        "com.rifsxd.ksunext",

        // SukiSU Ultra
        "com.sukisu.ultra",

        // APatch
        "me.bmax.apatch",

        // APatch Next
        "me.garfieldhan.apatch.next",

        // SuperSU
        "eu.chainfire.supersu",

        // Superuser
        "com.koushikdutta.superuser",

        // KingRoot
        "com.kingroot.kinguser",

        // Kingo Root
        "com.kingo.root"
    };

    public RootAppDetector() {
        super("root_app", DetectionCategory.ROOT);
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        PackageManager packageManager = context.getPackageManager();

        List<DetectionEvidence> evidence = new ArrayList<>();

        for (String packageName : ROOT_APP_PACKAGES) {
            if (PackagesUtils.isPackageInstalled(packageManager, packageName)) {
                evidence.add(new DetectionEvidence(
                    "PACKAGE",
                    packageName,
                    "发现管理 Root 的相关应用"
                ));
            }
        }

        if (evidence.isEmpty()) {
            return new DetectionResult(
                getId(),
                getCategory(),
                DetectionStatus.NOT_DETECTED,
                RiskLevel.NONE,
                evidence
            );
        }
        return new DetectionResult(
            getId(),
            getCategory(),
            DetectionStatus.DETECTED,
            RiskLevel.MEDIUM, // 发现包不代表已经 root 了，所以这里定义为中等风险
            evidence
        );
    }
}
