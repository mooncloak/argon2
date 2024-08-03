package com.mooncloak.kodetools.argon2

import org.kotlincrypto.SecureRandom

/**
 * Creates a [HashFunction] that uses the Argon2id hashing algorithm.
 *
 * @param [salt] A salt value that is used during the hashing process. This must be a [UByteArray]
 * whose size is `16`. To obtain a random and valid length salt, use the
 * [HashFunction.Companion.argon2Salt] function.
 *
 * @param [pepper] A pepper value that is used during the hashing process. This is similar to a
 * [salt] but adds a application-wide value for uniqueness. Defaults to `null`.
 *
 * @param [outputLength] The output length of the resulting [ByteArray] from invoking the
 * [HashFunction.invoke] function. This value must be at least `16`. Defaults to `32`.
 *
 * @param [iterations] The maximum amount of computations to perform. Raising this number will
 * make the function require more CPU cycles to compute a key. This number must be between `1UL`
 * and `4294967295UL`. Defaults to `2` which is recommended by OWASP when using 19MB of memory.
 *
 * @param [parallelism] The amount of parallelism. Defaults to `1`.
 *
 * @param [memory] The maximum amount of memory, in bytes, that the function will use.
 * Defaults to 19MB which is recommended by OWASP.
 *
 * @param [variant] The [Argon2Variant] of the hash function to perform. It is recommnded to use
 * [Argon2Variant.ID]. Defaults to [Argon2Variant.ID].
 *
 * @param [version] The [Argon2Version] of the Argon2 hash function to use. Defaults to
 * [Argon2Version.Default]. Note that any value may not be supported.
 *
 * @return A [HashFunction] that performs the Argon2id hashing algorithm.
 *
 * @see [HashFunction.Companion.argon2Salt]
 * @see [Wikipedia Argon2 Entry](https://en.wikipedia.org/wiki/Argon2)
 * @see [OWASP Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
 * @see [RFC-9106](https://datatracker.ietf.org/doc/rfc9106/)
 */
@ExperimentalArgon2Api
@OptIn(ExperimentalUnsignedTypes::class)
public fun HashFunction.Companion.argon2(
    salt: ByteArray,
    pepper: ByteArray? = null,
    outputLength: UInt = 32u,
    iterations: UInt = 2u,
    parallelism: UInt = 1u,
    memory: UInt = 19u * 1024u * 1024u, // 19MB
    variant: Argon2Variant = Argon2Variant.ID,
    version: Argon2Version = Argon2Version.Default
): HashFunction = Argon2HashFunction(
    outputLength = outputLength,
    salt = salt,
    pepper = pepper,
    iterations = iterations,
    parallelism = parallelism,
    memory = memory,
    variant = variant,
    version = version
)

/**
 * Retrieves a randomly generated salt value that is valid for the Argon2 hashing algorithm.
 *
 * @see [HashFunction.Companion.argon2]
 */
@ExperimentalArgon2Api
public fun HashFunction.Companion.argon2Salt(count: Int = 16): ByteArray =
    SecureRandom().nextBytesOf(count = count)

@ExperimentalUnsignedTypes
@ExperimentalArgon2Api
internal class Argon2HashFunction internal constructor(
    private val outputLength: UInt,
    private val salt: ByteArray,
    private val pepper: ByteArray?,
    private val iterations: UInt,
    private val parallelism: UInt,
    private val memory: UInt,
    private val variant: Argon2Variant,
    private val version: Argon2Version
) : HashFunction {

    override suspend fun hash(source: ByteArray): ByteArray {
        val argon2HashFunction = Argon2Impl(
            memory = memory.toInt(),
            iterations = iterations.toInt(),
            parallelism = parallelism.toInt(),
            outputLength = outputLength.toInt(),
            variant = variant,
            version = version.value
        )

        return argon2HashFunction.hash(
            plainTextPassword = source,
            salt = salt,
            pepper = pepper
        )
    }
}
