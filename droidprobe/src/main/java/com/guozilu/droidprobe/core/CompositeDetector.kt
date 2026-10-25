package com.guozilu.droidprobe.core

import android.content.Context

/**
 * 一个抽象类，继承了 AbstractDetector，用来同时完成多个检测分支
 * 在该构造该类实例时，应该传递这些检测分支，detectChildren() 会调用这些 Detector.detect(context)
 * 应在重写 doDetect() 方法时，在其中调用 detectChildren() 方法来完成对应的逻辑，否则这些子分支的检测，
 * 将不会被执行
 */
abstract class CompositeDetector(
    id: String,
    category: DetectionCategory,
    private val detectors: List<Detector>
) : AbstractDetector(id, category) {

    /**
     * 遍历 detectors，逐个执行 Detector.detect(context)
     * 将返回结果聚合成一个 List&lt;DetectionResult&gt; results
     * @param context Context context 上下文
     * @return 所有分支的 Detector 的检测结果的聚合
     */
    protected fun detectChildren(context: Context?): MutableList<DetectionResult> {
        val results: MutableList<DetectionResult> = ArrayList()
        detectors.forEach { detector -> results.add(detector.detect(context)) }
        return results
    }

    override fun getId(): String = id

    override fun getCategory(): DetectionCategory = category

    companion object {
        private const val TAG: String = "CompositeDetector"
    }
}
