package dev.webauthn.samples.composepasskey.ui.previews

import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview

@Preview(name = "Authentication · light")
@Composable
private fun AuthPreview() { SampleGallery("auth", darkTheme = false) }

@Preview(name = "Authentication · dark")
@Composable
private fun DarkPreview() { SampleGallery("auth", darkTheme = true) }

@Preview(name = "Platform prompt · busy")
@Composable
private fun BusyPreview() { SampleGallery("busy") }

@Preview(name = "Registration complete")
@Composable
private fun SuccessPreview() { SampleGallery("success") }

@Preview(name = "Cancelled")
@Composable
private fun CancelledPreview() { SampleGallery("cancelled") }

@Preview(name = "Server rejection")
@Composable
private fun RejectedPreview() { SampleGallery("rejected") }

@Preview(name = "Connection error")
@Composable
private fun ErrorPreview() { SampleGallery("error") }

@Preview(name = "PRF unavailable")
@Composable
private fun UnsupportedPreview() { SampleGallery("unsupported") }

@Preview(name = "Active PRF session")
@Composable
private fun SessionPreview() { SampleGallery("session") }

@Preview(name = "Encrypted and decrypted")
@Composable
private fun EncryptedPreview() { SampleGallery("encrypted") }

@Preview(name = "PRF prompt · busy")
@Composable
private fun PrfBusyPreview() { SampleGallery("prf-busy") }

@Preview(name = "Tablet", widthDp = 1100, heightDp = 850)
@Composable
private fun TabletPreview() { SampleGallery("session") }

@Preview(name = "Compact · large type", widthDp = 320, heightDp = 700, fontScale = 1.5f)
@Composable
private fun LargeTypePreview() { SampleGallery("auth") }
