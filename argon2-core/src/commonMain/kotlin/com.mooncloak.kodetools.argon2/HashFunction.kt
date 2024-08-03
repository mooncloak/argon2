package com.mooncloak.kodetools.argon2

import kotlin.coroutines.cancellation.CancellationException

/**
 * An interface for a generic hash function. The input and output is expected to be of type
 * [ByteArray].
 */
@ExperimentalArgon2Api
@OptIn(ExperimentalUnsignedTypes::class)
public fun interface HashFunction {

    /**
     * Performs the hash function on the provided [source] to generate a [UByteArray] value.
     */
    @Throws(HashException::class, CancellationException::class)
    public suspend fun hash(source: UByteArray): UByteArray

    public companion object
}

/**
 * Converts the provided [source] to a [UByteArray].
 *
 * @see [HashFunction.invoke]
 */
@ExperimentalArgon2Api
@OptIn(ExperimentalUnsignedTypes::class)
public suspend operator fun HashFunction.invoke(source: UByteArray): UByteArray =
    hash(source = source)

/**
 * Converts the provided [source] to a [UByteArray].
 *
 * @see [HashFunction.invoke]
 */
@ExperimentalArgon2Api
@OptIn(ExperimentalUnsignedTypes::class)
public suspend operator fun HashFunction.invoke(source: ByteArray): UByteArray =
    hash(source = source.toUByteArray())

/**
 * Converts the provided [source] to a [UByteArray] using UTF-8 encoding and calls the [invoke]
 * function on the result.
 *
 * @see [HashFunction.invoke]
 */
@ExperimentalArgon2Api
@OptIn(ExperimentalUnsignedTypes::class)
public suspend operator fun HashFunction.invoke(source: CharSequence): UByteArray =
    hash(source = source.toString().encodeToByteArray().asUByteArray())
