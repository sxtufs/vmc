package com.vmp.packer

import android.content.Context
import android.util.AttributeSet
import android.view.View
import android.widget.ListView

/**
 * ListView capped at maxHeightPx during layout: short lists stay compact, long
 * ones scroll internally. onMeasure is the correct place - ListView measures ALL
 * children under AT_MOST, unlike a post-show measure() call.
 */
class MaxHeightListView : ListView {
    constructor(context: Context) : super(context)
    constructor(context: Context, attrs: AttributeSet?) : super(context, attrs)

    var maxHeightPx: Int = Int.MAX_VALUE

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        super.onMeasure(
            widthMeasureSpec,
            View.MeasureSpec.makeMeasureSpec(maxHeightPx, View.MeasureSpec.AT_MOST)
        )
    }
}
