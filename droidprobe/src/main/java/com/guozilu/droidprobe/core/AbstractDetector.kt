package com.guozilu.droidprobe.core

import android.content.Context
import android.util.Log

/**
 * 一个抽象类，实现了 Detector 接口，继承该类时，应该实现 doDetect 方法以进行检测功能
 */
abstract class AbstractDetector protected constructor(
    override val id: String,
    override val category: DetectionCategory
) : Detector {
    final override fun detect(context: Context?): DetectionResult {
        return try {
            doDetect(context)
        }
        catch (throwable: Throwable) {
            createErrorResult(throwable)
        }
    }

    /**
     * 最核心的检测函数部分应该在这里实现
     * @param context Context 上下文
     * @return DetectionResult 检测结果
     */
    protected abstract fun doDetect(context: Context?): DetectionResult

    /**
     * 检测过程中发生了异常，具体就是打印一串异常日志，然后返回发生错误时应该返回的检测结果
     * @param throwable 发生的异常
     * @return 发生异常时应该得到的 DetectionResult 检测结果
     */
    private fun createErrorResult(throwable: Throwable): DetectionResult {
        Log.e(TAG, "A throwable was caught in AbstractDetector.detect()", throwable)
        return DetectionResult(
            id, category, DetectionStatus.ERROR,
            RiskLevel.UNKNOWN, mutableListOf()
        )
    }

    companion object {
        private const val TAG: String = "AbstractDetector";
    }
}
