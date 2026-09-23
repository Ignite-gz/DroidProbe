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
 * 检查潜在的可能与 root 有关的 app，比如 MT 管理器，Xposed 管理器等
 * 这些软件的存在虽然不能直接说明 root 了，但是可以认为应该提高风险等级
 */
public final class PotentiallyRiskyAppDetector extends AbstractDetector {
    private static final String TAG = "PotentiallyRiskyAppDetector";

    /**
     * 可能会有人有疑问说这些软件装在手机上不能说明什么，但一个正常的用户是不会安装这些软件的，
     * 我们在这里也没有直接把这认为就是手机已经 root，只是作为一个中低风险向上传递
     * 这个名单部分参考了 RootBeer(<a href="https://github.com/scottyab/rootbeer">RootBeer</a>)
     */
    private static final String[] POTENTIALLY_RISKY_APP_PACKAGES = {
        // =========================================================
        // APK / DEX / Smali 编辑与逆向工具
        // =========================================================

        // MT 管理器
        "bin.mt.plus",
        "bin.mt.plus.canary",

        // NP 管理器
        "com.wn.app.np",
        "player.normal.np",

        // 算法助手
        "com.junge.algorithmaide",

        // Apktool M
        "ru.maximoff.apktool",

        // APK Editor
        "com.gmail.heagoo.apkeditor",
        "com.gmail.heagoo.apkeditor.pro",

        // Xposed Installer
        "de.robv.android.xposed.installer",

        // EdXposed Manager
        "com.solohsu.android.edxp.manager",
        "org.meowcat.edxposed.manager",

        // LSPosed Manager
        "org.lsposed.manager",

        // LSPatch
        "org.lsposed.lspatch",  // LSPatch 不需要 root，但我们还是把它加入了

        // VirtualXposed
        "io.va.exposed",

        // Hide My Applist
        "com.tsng.hidemyapplist",

        // =========================================================
        // Root 隐藏 / 环境隐藏
        // =========================================================

        // RootCloak
        "com.devadvance.rootcloak",
        "com.devadvance.rootcloakplus",

        // HideMyRoot
        "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree",

        // Substrate
        "com.saurik.substrate",

        // Temporary Root / Root Hide
        "com.zachspong.temprootremovejb",

        // =========================================================
        // 应用修改 / 破解 / 运行时修改工具
        // =========================================================

        // Lucky Patcher
        "com.dimonvideo.luckypatcher",
        "com.chelpus.lackypatch",
        "com.chelpus.luckypatcher",

        // Lucky Patcher 相关伪 In-App Billing 服务
        "com.android.vending.billing.InAppBillingService.COIN",
        "com.android.vending.billing.InAppBillingService.LUCK",

        // Freedom
        "cc.madkite.freedom",

        // =========================================================
        // 游戏修改 / 内存修改工具
        // =========================================================

        // GameGuardian
        "catch_.me_.if_.you_.can_",

        // GameCIH
        "com.cih.game_cih",

        // XmodGames
        "com.xmodgame",

        // =========================================================
        // ROM / 系统修改相关工具
        // =========================================================

        // ROM Manager
        "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license",

        // App Quarantine
        "com.ramdroid.appquarantine",
        "com.ramdroid.appquarantinepro",

        // =========================================================
        // 第三方应用市场 / 其他历史高风险工具
        // =========================================================

        // Blackmart
        "com.blackmartalpha",
        "org.blackmart.market",

        // RepoDroid
        "com.repodroid.app",

        // Mobilism
        "org.mobilism.android",

        // 其他历史工具
        "com.allinone.free",
        "org.creeplays.hack",
        "com.baseappfull.fwd",
        "com.zmapp",
        "com.dv.marketmod.installer",
        "com.android.wp.net.log",
        "com.android.camera.update",

        // 历史特殊包名
        "com.charles.lpoqasert",
    };

    public PotentiallyRiskyAppDetector() {
        super("potentially_risky_app", DetectionCategory.ROOT);
    }

    @Override
    protected DetectionResult doDetect(Context context) {
        PackageManager packageManager = context.getPackageManager();

        List<DetectionEvidence> evidence = new ArrayList<>();

        for (String packageName : POTENTIALLY_RISKY_APP_PACKAGES) {
            if (PackagesUtils.isPackageInstalled(packageManager, packageName)) {
                evidence.add(new DetectionEvidence(
                    "PACKAGE",
                    packageName,
                    "发现潜在的风险应用"
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
            RiskLevel.MEDIUM_LOW,
            evidence
        );
    }
}
