package dev.webauthn.samples.passkeycli

import kotlinx.coroutines.runBlocking
import kotlin.system.exitProcess

public fun main(args: Array<String>): Unit = runBlocking {
    val exitCode = CliApplication().run(args)
    if (exitCode != 0) {
        exitProcess(exitCode)
    }
}
