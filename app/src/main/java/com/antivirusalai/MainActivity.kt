package com.antivirusalai

import android.app.PictureInPictureParams
import android.content.Intent
import android.content.res.Configuration
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.util.Rational
import androidx.compose.runtime.mutableStateOf
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.antivirusalai.intel.ThreatFeedScheduler

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Render the primary UI before scheduling optional background work.
        // A WorkManager initialization/scheduling issue must never prevent launch.
        setContent { AntivirusApp(inPictureInPicture = pictureInPictureState.value) }

        try {
            ThreatFeedScheduler.schedule(applicationContext)
        } catch (error: Exception) {
            Log.w(TAG, "Threat-feed background scheduling was deferred.", error)
        }

        // Restore an explicitly enabled protection service when the user reopens the app.
        if (ProtectionRuntime.isEnabled(applicationContext)) {
            try {
                startForegroundService(Intent(applicationContext, ProtectionService::class.java))
            } catch (error: Exception) {
                Log.w(TAG, "Previously enabled protection could not be restored.", error)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Re-establish the user-enabled monitor when the activity returns after
        // Android has reclaimed the process. Never start it if the user turned it off.
        if (ProtectionRuntime.isEnabled(applicationContext)) {
            runCatching {
                startForegroundService(Intent(this, ProtectionService::class.java))
            }.onFailure { error ->
                Log.w(TAG, "The previously enabled protection service could not be resumed.", error)
            }
        }
    }

    override fun onUserLeaveHint() {
        super.onUserLeaveHint()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && ScanRuntime.isActive) {
            try {
                enterPictureInPictureMode(PictureInPictureParams.Builder()
                    .setAspectRatio(Rational(16, 9)).build())
            } catch (error: Exception) {
                Log.w(TAG, "Picture-in-picture could not be started for the active scan.", error)
            }
        }
    }

    override fun onPictureInPictureModeChanged(isInPictureInPictureMode: Boolean, newConfig: Configuration) {
        super.onPictureInPictureModeChanged(isInPictureInPictureMode, newConfig)
        pictureInPictureState.value = isInPictureInPictureMode
    }

    private val pictureInPictureState = mutableStateOf(false)

    private companion object {
        const val TAG = "AntivirusAlAi"
    }
}
