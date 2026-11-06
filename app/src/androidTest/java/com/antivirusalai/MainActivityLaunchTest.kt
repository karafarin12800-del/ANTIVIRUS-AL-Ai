package com.antivirusalai

import android.graphics.BitmapFactory
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityLaunchTest {
    @Test
    fun guardianArtworkResourceDecodesToBitmap() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val bitmap = BitmapFactory.decodeResource(
                    activity.resources,
                    R.drawable.guardian_robot
                )
                assertNotNull("Guardian robot resource must decode on Android", bitmap)
                assertTrue("Guardian robot bitmap must have a valid width", bitmap!!.width > 0)
                assertTrue("Guardian robot bitmap must have a valid height", bitmap.height > 0)
            }
        }
    }

    @Test
    fun launcherActivityStartsAndRendersItsWindow() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertNotNull(activity.window)
                assertNotNull(activity.window.decorView)
            }
        }
    }
}
