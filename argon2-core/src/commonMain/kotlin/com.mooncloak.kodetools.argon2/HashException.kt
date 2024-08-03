package com.mooncloak.kodetools.argon2

/**
 * Represents an exception that can occur when a [HashFunction] is invoked.
 */
public open class HashException public constructor(
    message: String?,
    cause: Throwable?
) : RuntimeException(message, cause)
