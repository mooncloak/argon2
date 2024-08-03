package com.mooncloak.kodetools.argon2

import kotlin.coroutines.cancellation.CancellationException

/**
 * An interface for a generic hash function. The input and output is expected to be of type
 * [ByteArray].
 */
@ExperimentalArgon2Api
public fun interface HashFunction {

    /**
     * Performs the hash function on the provided [source] to generate a [ByteArray] value.
     */
    @Throws(HashException::class, CancellationException::class)
    public suspend fun hash(source: ByteArray): ByteArray

    public companion object
}

/**
 * Converts the provided [source] to a [UByteArray].
 *
 * @see [HashFunction.invoke]
 */
@ExperimentalArgon2Api
@OptIn(ExperimentalUnsignedTypes::class)
public suspend operator fun HashFunction.invoke(source: UByteArray): ByteArray =
    hash(source = source.toByteArray())

/**
 * Converts the provided [source] to a [UByteArray].
 *
 * @see [HashFunction.invoke]
 */
@ExperimentalArgon2Api
public suspend operator fun HashFunction.invoke(source: ByteArray): ByteArray =
    hash(source = source)

/**
 * Converts the provided [source] to a [UByteArray] using UTF-8 encoding and calls the [invoke]
 * function on the result.
 *
 * @see [HashFunction.invoke]
 */
@ExperimentalArgon2Api
public suspend operator fun HashFunction.invoke(source: CharSequence): ByteArray =
    hash(source = source.toString().encodeToByteArray())
