package com.mooncloak.kodetools.argon2

import com.mooncloak.kodetools.argon2.Argon2HashFunction.Companion.ARGON2_VERSION_10
import org.kotlincrypto.SecureRandom

/**
 * Creates a [HashFunction] that uses the Argon2id hashing algorithm.
 *
 * @param [outputLength] The output length of the resulting [UByteArray] from invoking the
 * [HashFunction.invoke] function. This value must be at least `16U`.
 *
 * @param [salt] A salt value that is used during the hashing process. This must be a [UByteArray]
 * whose size is `16`. To obtain a random and valid length salt, use the
 * [HashFunction.Companion.argon2idSalt] function.
 *
 * @param [operationLimit] The maximum amount of computations to perform. Raising this number will
 * make the function require more CPU cycles to compute a key. This number must be between `1UL`
 * and `4294967295UL`. Defaults to `1UL` which is recommended by OWASP when using 19MB of memory.
 *
 * @param [maxMemoryInBytes] The maximum amount of memory, in bytes, that the function will use.
 * Defaults to 19MB which is recommended by OWASP.
 *
 * @return A [HashFunction] that performs the Argon2id hashing algorithm.
 *
 * @see [HashFunction.Companion.argon2idSalt]
 * @see [Wikipedia Argon2 Entry](https://en.wikipedia.org/wiki/Argon2)
 * @see [OWASP Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
 */
@ExperimentalArgon2Api
@OptIn(ExperimentalUnsignedTypes::class)
public fun HashFunction.Companion.argon2id(
    outputLength: Int,
    salt: UByteArray,
    operationLimit: ULong = 1uL,
    maxMemoryInBytes: Int = 19 * 1024 * 1024 // 19MB
): HashFunction = Argon2idHashFunction(
    outputLength = outputLength,
    salt = salt,
    operationLimit = operationLimit,
    maxMemoryInBytes = maxMemoryInBytes
)

/**
 * Retrieves a randomly generated salt value that is valid for the Argon2id hashing algorithm.
 *
 * @see [HashFunction.Companion.argon2id]
 */
@ExperimentalArgon2Api
@OptIn(ExperimentalUnsignedTypes::class)
public fun HashFunction.Companion.argon2idSalt(count: Int = 16): UByteArray =
    SecureRandom().nextBytesOf(count = count).toUByteArray()

@ExperimentalUnsignedTypes
@ExperimentalArgon2Api
internal class Argon2idHashFunction internal constructor(
    private val outputLength: Int,
    private val salt: UByteArray,
    private val operationLimit: ULong,
    private val maxMemoryInBytes: Int
) : HashFunction {

    override suspend fun hash(source: UByteArray): UByteArray {
        val argon2HashFunction = Argon2HashFunction(
            memory = maxMemoryInBytes,
            iterations = operationLimit.toInt(), // TODO: ?
            parallelism = 1, // TODO: ?
            outputLength = outputLength,
            variant = Argon2.ID,
            version = ARGON2_VERSION_10 // TODO: ?
        )

        return argon2HashFunction.hash(
            plainTextPassword = source.toByteArray(),
            salt = salt.toByteArray(),
            pepper = null
        )
    }
}
