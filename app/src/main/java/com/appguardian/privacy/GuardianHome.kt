package com.appguardian.privacy

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.ExperimentalAnimationApi
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp

@Composable
internal fun GuardianHeader() {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = RoundedCornerShape(14.dp)) {
            GuardianMark(false, Modifier.padding(8.dp).size(32.dp))
        }
        Text("AppGuardian", style = MaterialTheme.typography.headlineMedium)
    }
}

@OptIn(ExperimentalAnimationApi::class)
@Composable
internal fun ApkEntryCard(scanning: Boolean, allowChoose: Boolean, choose: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    Surface(shape = RoundedCornerShape(26.dp), color = colors.surfaceContainer) {
        Box(Modifier.background(Brush.linearGradient(listOf(Color(0xFF25423B), Color(0xFF162925))))) {
            Column(Modifier.fillMaxWidth().padding(22.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("APK review", style = MaterialTheme.typography.headlineSmall)
                        AnimatedContent(
                            targetState = scanning,
                            transitionSpec = { fadeIn(tween(180)).togetherWith(fadeOut(tween(140))) },
                            label = "APK review status"
                        ) { active ->
                            Text(
                                if (active) "Reading APK evidence…" else "Check a file before installing it.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = colors.onSurfaceVariant
                            )
                        }
                    }
                    GuardianMark(scanning, Modifier.size(50.dp))
                }
                Text("The APK stays on this device during local review.", style = MaterialTheme.typography.bodyMedium)
                Button(enabled = allowChoose && !scanning, onClick = choose) { Text("Choose APK") }
            }
        }
    }
}

@Composable
private fun GuardianMark(active: Boolean, modifier: Modifier) {
    val accent = MaterialTheme.colorScheme.primary
    val angle = if (active) {
        val animation = rememberInfiniteTransition(label = "APK scan pulse")
        val value by animation.animateFloat(
            initialValue = -90f,
            targetValue = 270f,
            animationSpec = infiniteRepeatable(tween(1000, easing = LinearEasing), RepeatMode.Restart),
            label = "APK scan arc"
        )
        value
    } else -90f
    Canvas(modifier) {
        val w = size.width
        val h = size.height
        val shield = Path().apply {
            moveTo(w * .5f, h * .15f)
            lineTo(w * .79f, h * .27f)
            lineTo(w * .79f, h * .51f)
            quadraticBezierTo(w * .79f, h * .72f, w * .5f, h * .87f)
            quadraticBezierTo(w * .21f, h * .72f, w * .21f, h * .51f)
            lineTo(w * .21f, h * .27f)
            close()
        }
        drawPath(shield, accent.copy(alpha = .13f))
        drawPath(shield, accent, style = Stroke(width = 1.5.dp.toPx()))
        drawLine(accent, Offset(w * .39f, h * .51f), Offset(w * .47f, h * .60f), 1.8.dp.toPx(), StrokeCap.Round)
        drawLine(accent, Offset(w * .47f, h * .60f), Offset(w * .63f, h * .42f), 1.8.dp.toPx(), StrokeCap.Round)
        if (active) {
            drawArc(accent, angle, 65f, false, style = Stroke(width = 1.6.dp.toPx(), cap = StrokeCap.Round))
        }
    }
}
