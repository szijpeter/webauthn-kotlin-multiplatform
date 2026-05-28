package dev.webauthn.client.ios

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.allocArrayOf
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.create
import platform.posix.memcpy

@OptIn(ExperimentalForeignApi::class)
internal fun NSData.toByteArray(): ByteArray {
    if (length == 0uL) return ByteArray(0)
    return ByteArray(length.toInt()).apply {
        usePinned { pinned ->
            memcpy(pinned.addressOf(0), bytes, length)
        }
    }
}

@OptIn(BetaInteropApi::class, ExperimentalForeignApi::class)
internal fun ByteArray.toNSData(): NSData = memScoped {
    if (isEmpty()) return NSData()
    return NSData.create(bytes = allocArrayOf(this@toNSData), length = size.toULong())
}
