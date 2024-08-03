package com.mooncloak.kodetools.argon2

/**
 * Blake2b implementation converted from a Java implementation.
 *
 * @param digestSize size of the digest in bytes.
 *
 * @see [Java Reference Implementation](https://github.com/Password4j/password4j/blob/master/src/main/java/com/password4j/Blake2b.java)
 * @see [Java Reference Apache 2 License](https://github.com/Password4j/password4j/blob/master/LICENSE)
 * @see [Wikipedia Explanation of Blake2b](https://en.wikipedia.org/wiki/BLAKE_(hash_function))
 */
internal class Blake2b internal constructor(digestSize: Int) {

    private val digestLength: Int

    private val keyLength: Int

    private val buffer: ByteArray

    private val internalState = LongArray(16)

    private var bufferPos = 0

    private var chainValue: LongArray = LongArray(8)

    private var t0 = 0L

    private var t1 = 0L

    private var f0 = 0L

    init {
        if (digestSize < 1 || digestSize > 64) {
            throw IllegalArgumentException("BLAKE2b digest bytes length must be not greater than 64")
        }

        buffer = ByteArray(BLOCK_LENGTH_BYTES)
        keyLength = 0
        digestLength = digestSize

        init()
    }

    // initialize chainValue
    private fun init() {
        chainValue[0] =
            IV[0] xor (digestLength.toLong() or (keyLength.toLong() shl 8) or 0x1010000L)
        chainValue[1] = IV[1]
        chainValue[2] = IV[2]
        chainValue[3] = IV[3]
        chainValue[4] = IV[4]
        chainValue[5] = IV[5]
        chainValue[6] = IV[6]
        chainValue[7] = IV[7]
    }

    private fun initializeInternalState() {
        arraycopy(chainValue, 0, internalState, 0, chainValue.size)
        arraycopy(IV, 0, internalState, chainValue.size, 4)
        internalState[12] = t0 xor IV[4]
        internalState[13] = t1 xor IV[5]
        internalState[14] = f0 xor IV[6]
        internalState[15] = IV[7] // ^ f1 with f1 = 0
    }

    /**
     * update the message digest with a block of bytes.
     *
     * @param message the byte array containing the data.
     * @param offset  the offset into the byte array where the data starts.
     * @param length     the length of the data.
     */
    fun update(
        message: ByteArray,
        offset: Int = 0,
        length: Int = message.size
    ) {
        var remainingLength = 0

        if (bufferPos != 0) {
            remainingLength = BLOCK_LENGTH_BYTES - bufferPos
            if (remainingLength < length) {
                arraycopy(message, offset, buffer, bufferPos, remainingLength)
                t0 += BLOCK_LENGTH_BYTES.toLong()
                if (t0 == 0L) {
                    t1++
                }
                compress(buffer, 0)
                bufferPos = 0
                buffer.fill(0.toByte()) // clear buffer
            } else {
                arraycopy(message, offset, buffer, bufferPos, length)
                bufferPos += length
                return
            }
        }
        val blockWiseLastPos = offset + length - BLOCK_LENGTH_BYTES
        var messagePos = offset + remainingLength
        while (messagePos < blockWiseLastPos) {
            t0 += BLOCK_LENGTH_BYTES.toLong()
            if (t0 == 0L) {
                t1++
            }
            compress(message, messagePos)
            messagePos += BLOCK_LENGTH_BYTES
        }

        // fill the buffer with left bytes, this might be a full block
        arraycopy(message, messagePos, buffer, 0, offset + length - messagePos)
        bufferPos += offset + length - messagePos
    }

    /**
     * close the digest, producing the final digest value. The doFinal
     * call leaves the digest reset.
     * Key, salt and personal string remain.
     *
     * @param out       the array the digest is to be copied into.
     * @param outOffset the offset into the out array the digest is to start at.
     */
    fun doFinal(out: ByteArray, outOffset: Int) {
        f0 = -0x1L
        t0 += bufferPos.toLong()
        if (bufferPos > 0 && t0 == 0L) {
            t1++
        }
        compress(buffer, 0)
        buffer.fill(0.toByte())// Holds eventually the key if input is null
        internalState.fill(0L)

        var i = 0
        while (i < chainValue.size && (i * 8 < digestLength)) {
            val bytes: ByteArray = longToLittleEndian(chainValue[i])

            if (i * 8 < digestLength - 8) {
                arraycopy(bytes, 0, out, outOffset + i * 8, 8)
            } else {
                arraycopy(bytes, 0, out, outOffset + i * 8, digestLength - (i * 8))
            }
            i++
        }

        chainValue.fill(0L)

        reset()
    }

    /**
     * Reset the digest back to it's initial state.
     * The key, the salt and the personal string will
     * remain for further computations.
     */
    fun reset() {
        bufferPos = 0
        f0 = 0L
        t0 = 0L
        t1 = 0L
        chainValue = LongArray(8)
        buffer.fill(0.toByte())
        init()
    }

    private fun compress(message: ByteArray, messagePos: Int) {
        initializeInternalState()

        val m = LongArray(16)
        for (j in 0..15) {
            m[j] = littleEndianToLong(message, messagePos + j * 8)
        }

        for (round in 0 until ROUNDS) {
            // G apply to columns of internalState:m[blake2b_sigma[round][2 *
            // blockPos]] /+1

            functionG(
                m[SIGMA[round][0].toInt()],
                m[SIGMA[round][1].toInt()], 0, 4, 8, 12
            )
            functionG(
                m[SIGMA[round][2].toInt()],
                m[SIGMA[round][3].toInt()], 1, 5, 9, 13
            )
            functionG(
                m[SIGMA[round][4].toInt()],
                m[SIGMA[round][5].toInt()], 2, 6, 10, 14
            )
            functionG(
                m[SIGMA[round][6].toInt()],
                m[SIGMA[round][7].toInt()], 3, 7, 11, 15
            )
            // G apply to diagonals of internalState:
            functionG(
                m[SIGMA[round][8].toInt()],
                m[SIGMA[round][9].toInt()], 0, 5, 10, 15
            )
            functionG(
                m[SIGMA[round][10].toInt()],
                m[SIGMA[round][11].toInt()], 1, 6, 11, 12
            )
            functionG(
                m[SIGMA[round][12].toInt()],
                m[SIGMA[round][13].toInt()], 2, 7, 8, 13
            )
            functionG(
                m[SIGMA[round][14].toInt()],
                m[SIGMA[round][15].toInt()], 3, 4, 9, 14
            )
        }

        // update chain values:
        for (offset in chainValue.indices) {
            chainValue[offset] =
                chainValue[offset] xor internalState[offset] xor internalState[offset + 8]
        }
    }

    private fun functionG(m1: Long, m2: Long, posA: Int, posB: Int, posC: Int, posD: Int) {
        internalState[posA] = internalState[posA] + internalState[posB] + m1
        internalState[posD] = (internalState[posD] xor internalState[posA]).rotateRight(32)
        internalState[posC] = internalState[posC] + internalState[posD]
        internalState[posB] =
            (internalState[posB] xor internalState[posC]).rotateRight(24) // replaces 25 of BLAKE
        internalState[posA] = internalState[posA] + internalState[posB] + m2
        internalState[posD] = (internalState[posD] xor internalState[posA]).rotateRight(16)
        internalState[posC] = internalState[posC] + internalState[posD]
        internalState[posB] =
            (internalState[posB] xor internalState[posC]).rotateRight(63) // replaces 11 of BLAKE
    }

    companion object {

        private val IV = longArrayOf(
            0x6a09e667f3bcc908L, -0x4498517a7b3558c5L, 0x3c6ef372fe94f82bL, -0x5ab00ac5a0e2c90fL,
            0x510e527fade682d1L, -0x64fa9773d4c193e1L, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
        )

        private val SIGMA = arrayOf(
            byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            byteArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            byteArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            byteArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            byteArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            byteArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            byteArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            byteArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            byteArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            byteArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
            byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            byteArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3)
        )

        private const val ROUNDS = 12

        private const val BLOCK_LENGTH_BYTES = 128
    }
}
