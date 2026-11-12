package com.antivirusalai

import android.app.Application
import androidx.work.Configuration
import androidx.work.WorkManager

/**
 * Initializes WorkManager before any Activity or Compose content can request it.
 *
 * Its AndroidX Startup initializer is removed from the merged manifest so there
 * is exactly one initialization path and no ordering/double-initialization race.
 */
class AntivirusApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        WorkManager.initialize(this, Configuration.Builder().build())
    }
}
