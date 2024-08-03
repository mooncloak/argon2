package com.mooncloak.kodetools.argon2

import com.mooncloak.kodetools.argon2.Argon2Impl.Companion.ARGON2_VERSION_13
import kotlin.jvm.JvmInline

@JvmInline
@ExperimentalArgon2Api
public value class Argon2Version public constructor(
    public val value: Int
) {

    public companion object {

        public val Default: Argon2Version = Argon2Version(value = ARGON2_VERSION_13)
    }
}
