package com.guozilu.droidprobe.root

import android.content.Context
import com.guozilu.droidprobe.core.AbstractDetector
import com.guozilu.droidprobe.core.DetectionCategory
import com.guozilu.droidprobe.core.DetectionEvidence
import com.guozilu.droidprobe.core.DetectionResult
import com.guozilu.droidprobe.core.DetectionStatus
import com.guozilu.droidprobe.core.RiskLevel
import com.guozilu.droidprobe.utils.ProcessIdentityUtils

/**
 * 这个类检查 app 所处进程的 uid，euid，gid，egid，groups
 * 如果 uid == 0，euid == 0，gid == 0，egid == 0，groups[i] == 0
 * 则说明有 root 用户
 */
class ProcessIdentityDetector : AbstractDetector(
    "process_identity",
    DetectionCategory.ROOT) {

    override fun doDetect(context: Context?): DetectionResult {
        val evidences: MutableList<DetectionEvidence> = ArrayList()

        // uid
        if (ProcessIdentityUtils.getUid() == 0) {
            evidences.add(DetectionEvidence(
                "UID",
                "uid=0",
                "进程的 uid 是 0"
            ))
        }

        // euid 有效 uid
        if (ProcessIdentityUtils.getEuid() == 0) {
            evidences.add(DetectionEvidence(
                "EUID",
                "euid=0",
                "进程的 euid 是 0"
            ))
        }

        // gid
        if (ProcessIdentityUtils.getGid() == 0) {
            evidences.add(DetectionEvidence(
                "GID",
                "gid=0",
                "进程的 gid 是 0"
            ))
        }

        // egid 有效 gid
        if (ProcessIdentityUtils.getEgid() == 0) {
            evidences.add(DetectionEvidence(
                "EGID",
                "egid=0",
                "进程的 egid 是 0"
            ))
        }

        // groups 补充组中是否有 root 组
        val index: Int? = rootInGroupsIndex()
        if (index != null) {
            evidences.add(DetectionEvidence(
                "GROUPS",
                "groups[$index]=0",
                "进程的 groups[$index] 是 0"
            ))
        }

        if (!evidences.isEmpty()) {
            return DetectionResult(
                id,
                category,
                DetectionStatus.DETECTED,
                RiskLevel.CRITICAL,
                evidences
            )
        }
        return DetectionResult(
            id,
            category,
            DetectionStatus.NOT_DETECTED,
            RiskLevel.NONE,
            evidences
        )
    }

    companion object {
        private const val TAG: String = "ProcessIdentityDetector"

        /**
         * 判断是否有 root 组在补充组中
         * @return 如果有就返回 root 所在组的索引，没有就返回 null
         */
        private fun rootInGroupsIndex(): Int? {
            val groups: IntArray = ProcessIdentityUtils.getGroups() ?: return null
            for (i in groups.indices) {
                if (groups[i] == 0) {
                    return i
                }
            }
            return null
        }
    }
}
