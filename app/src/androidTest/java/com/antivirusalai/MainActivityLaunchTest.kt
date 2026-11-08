package com.antivirusalai

import android.graphics.BitmapFactory
import android.view.ViewGroup
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityLaunchTest {
    @Test
    fun guardianArtworkResourceDecodesToBitmap() {
        withMainActivityScenario { scenario ->
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { activity ->
                val bitmap = requireNotNull(
                    BitmapFactory.decodeResource(
                        activity.resources,
                        R.drawable.guardian_robot
                    )
                ) { "Guardian robot drawable did not decode to a Bitmap on Android" }
                assertTrue("Guardian robot bitmap must have a valid width", bitmap.width > 0)
                assertTrue("Guardian robot bitmap must have a valid height", bitmap.height > 0)
            }
        }
    }

    @Test
    fun launcherActivityAttachesItsComposeContentAfterStartup() {
        withMainActivityScenario { scenario ->
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { activity ->
                assertNotNull("The launcher Activity must create a window.", activity.window)
                val content = activity.findViewById<ViewGroup>(android.R.id.content)
                assertNotNull("The Activity content host must exist.", content)
                assertTrue(
                    "setContent must attach a content view before startup is considered successful.",
                    content.childCount > 0
                )
                assertTrue(
                    "The Compose content root must be attached to the active window.",
                    content.getChildAt(0).isAttachedToWindow
                )
            }
        }
    }

    /**
     * Finish the launched Activity explicitly before closing its scenario.
     * This keeps ActivityScenario cleanup deterministic when the Activity has
     * transitioned to STOPPED during instrumentation teardown.
     */
    private fun withMainActivityScenario(
        block: (ActivityScenario<MainActivity>) -> Unit
    ) {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        try {
            block(scenario)
        } finally {
            try {
                scenario.onActivity { activity -> activity.finish() }
                InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            } finally {
                scenario.close()
            }
        }
    }
}
