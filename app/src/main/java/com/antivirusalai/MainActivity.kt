package com.antivirusalai

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.antivirusalai.intel.ThreatFeedScheduler

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ThreatFeedScheduler.schedule(applicationContext)
        setContent { AntivirusApp() }
    }
}
