package com.antivirusalai

import androidx.compose.foundation.Image
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource

/**
 * Displays the isolated guardian artwork from the Android drawable resources.
 *
 * Keeping the image as a real PNG resource avoids runtime Base64 decoding and
 * prevents malformed embedded image data from crashing the first composition.
 */
@Composable
internal fun GuardianRobotArtwork(modifier: Modifier = Modifier) {
    Image(
        painter = painterResource(id = R.drawable.guardian_robot),
        contentDescription = "ANTIVIRUS AL AI guardian robot",
        modifier = modifier,
        contentScale = ContentScale.Fit
    )
}
