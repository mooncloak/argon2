package com.mooncloak.kodetools.argon2

/**
 * Enum containing the different variations of Argon2.
 *
 * Converted from Java from the following source:
 * https://github.com/Password4j/password4j/blob/master/src/main/java/com/password4j/types/Argon2.java#L26
 * Apache 2 license:
 * https://github.com/Password4j/password4j/blob/master/LICENSE
 */
@ExperimentalArgon2Api
public enum class Argon2Variant {

    /**
     * It maximizes resistance to GPU cracking attacks.
     * It accesses the memory array in a password dependent order, which reduces the possibility of time–memory
     * trade-off (TMTO) attacks, but introduces possible side-channel attacks
     */
    D,

    /**
     * It is optimized to resist side-channel attacks. It accesses the memory array in a password independent order.
     */
    I,

    /**
     * It is a hybrid version. It follows the Argon2i approach for the first half pass over memory and the Argon2d
     * approach for subsequent passes. It is recommended to use Argon2id except when there are reasons to prefer one of
     * the other two modes.
     */
    ID
}
