package com.antivirusalai

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.antivirusalai.intel.ThreatFeedScheduler

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Render the primary UI before scheduling optional background work.
        // A WorkManager initialization/scheduling issue must never prevent launch.
        setContent { AntivirusApp() }

        try {
            ThreatFeedScheduler.schedule(applicationContext)
        } catch (error: Exception) {
            Log.w(TAG, "Threat-feed background scheduling was deferred.", error)
        }
    }

    private companion object {
        const val TAG = "AntivirusAlAi"
    }
}
