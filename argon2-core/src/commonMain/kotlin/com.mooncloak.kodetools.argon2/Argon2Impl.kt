package com.mooncloak.kodetools.argon2

import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

/**
 * Class containing the implementation of Argon2 function and its parameters.
 *
 * Converted from Java.
 *
 * @see [Java Reference](https://github.com/Password4j/password4j/blob/master/src/main/java/com/password4j/Argon2Function.java)
 * @see [Java Reference Apache 2 License](https://github.com/Password4j/password4j/blob/master/LICENSE)
 * @see [Wikipedia Argon2 Explanation](https://en.wikipedia.org/wiki/Argon2)
 */
@ExperimentalArgon2Api
internal class Argon2Impl internal constructor(
    /**
     * @return the memory in bytes
     * @since 1.5.2
     */
    val memory: Int,
    /**
     * @return the number of iterations
     * @since 1.5.2
     */
    val iterations: Int,
    /**
     * @return the degree of parallelism
     * @since 1.5.2
     */
    val parallelism: Int,
    /**
     * @return the length of the produced hash
     * @since 1.5.2
     */
    val outputLength: Int,
    val variant: Argon2Variant,
    /**
     * @return the version of the algorithm
     * @since 1.5.2
     */
    val version: Int
) {

    private val initialBlockMemory: Array<LongArray>

    private val segmentLength: Int

    private val laneLength: Int

    init {
        var memoryBlocks = this.memory

        if (this.memory < 2 * ARGON2_SYNC_POINTS * parallelism) {
            memoryBlocks = 2 * ARGON2_SYNC_POINTS * parallelism
        }

        segmentLength = memoryBlocks / (parallelism * ARGON2_SYNC_POINTS)
        this.laneLength = segmentLength * ARGON2_SYNC_POINTS

        memoryBlocks = segmentLength * (parallelism * ARGON2_SYNC_POINTS)

        initialBlockMemory = Array(memoryBlocks) {
            LongArray(
                ARGON2_QWORDS_IN_BLOCK
            )
        }

        for (i in 0 until memoryBlocks) {
            initialBlockMemory[i] = LongArray(ARGON2_QWORDS_IN_BLOCK)
        }
    }

    internal suspend fun hash(
        plainTextPassword: ByteArray,
        salt: ByteArray,
        pepper: ByteArray?
    ): ByteArray {
        val blockMemory = copyOf(initialBlockMemory)

        initialize(
            plainTextPassword = plainTextPassword,
            salt = salt,
            secret = pepper ?: ByteArray(0),
            additional = null,
            blockMemory = blockMemory
        )

        fillMemoryBlocks(blockMemory)

        return ending(blockMemory)
    }

    private fun initialize(
        plainTextPassword: ByteArray,
        salt: ByteArray,
        secret: ByteArray,
        additional: ByteArray?,
        blockMemory: Array<LongArray>
    ) {
        val blake2b = Blake2b(ARGON2_INITIAL_DIGEST_LENGTH)

        blake2b.update(intToLittleEndian(parallelism))
        blake2b.update(intToLittleEndian(outputLength))
        blake2b.update(intToLittleEndian(memory))
        blake2b.update(intToLittleEndian(iterations))
        blake2b.update(intToLittleEndian(version))
        blake2b.update(intToLittleEndian(variant.ordinal))

        updateWithLength(blake2b, plainTextPassword)

        updateWithLength(blake2b, salt)

        updateWithLength(blake2b, secret)

        updateWithLength(blake2b, additional)

        val initialHash = ByteArray(64)
        blake2b.doFinal(initialHash, 0)

        val zeroBytes = byteArrayOf(0, 0, 0, 0)
        val oneBytes = byteArrayOf(1, 0, 0, 0)

        val initialHashWithZeros = getInitialHashLong(initialHash, zeroBytes)
        val initialHashWithOnes = getInitialHashLong(initialHash, oneBytes)

        for (i in 0 until parallelism) {
            val iBytes: ByteArray = intToLittleEndian(i)

            arraycopy(
                iBytes,
                0,
                initialHashWithZeros,
                ARGON2_INITIAL_DIGEST_LENGTH + 4,
                4
            )
            arraycopy(
                iBytes,
                0,
                initialHashWithOnes,
                ARGON2_INITIAL_DIGEST_LENGTH + 4,
                4
            )

            var blockHashBytes = blake2bLong(initialHashWithZeros, ARGON2_BLOCK_SIZE)
            blockMemory[i * laneLength] = blockHashBytes.toLongArray()

            blockHashBytes = blake2bLong(initialHashWithOnes, ARGON2_BLOCK_SIZE)
            blockMemory[i * laneLength + 1] = blockHashBytes.toLongArray()
        }
    }

    private fun blake2bLong(input: ByteArray, outputLength: Int): ByteArray {
        var result = ByteArray(outputLength)
        val outlenBytes: ByteArray = intToLittleEndian(outputLength)

        val blake2bLength = 64

        if (outputLength <= blake2bLength) {
            result = simpleBlake2b(input, outlenBytes, outputLength)
        } else {
            var outBuffer: ByteArray

            outBuffer = simpleBlake2b(input, outlenBytes, blake2bLength)
            arraycopy(outBuffer, 0, result, 0, blake2bLength / 2)

            val r = (outputLength / 32) + (if (outputLength % 32 == 0) 0 else 1) - 2

            var position = blake2bLength / 2
            var i = 2
            while (i <= r) {
                outBuffer = simpleBlake2b(outBuffer, null, blake2bLength)

                arraycopy(outBuffer, 0, result, position, blake2bLength / 2)

                i++

                position += blake2bLength / 2
            }

            val lastLength = outputLength - 32 * r

            outBuffer = simpleBlake2b(outBuffer, null, lastLength)
            arraycopy(outBuffer, 0, result, position, lastLength)
        }

        return result
    }

    private fun simpleBlake2b(
        input: ByteArray,
        outlenBytes: ByteArray?,
        outputLength: Int
    ): ByteArray {
        val blake2b = Blake2b(outputLength)

        if (outlenBytes != null) blake2b.update(outlenBytes)

        blake2b.update(input)

        val buff = ByteArray(outputLength)

        blake2b.doFinal(buff, 0)

        return buff
    }

    private suspend fun fillMemoryBlocks(blockMemory: Array<LongArray>) {
        if (parallelism == 1) {
            fillMemoryBlockSingleThreaded(blockMemory)
        } else {
            fillMemoryBlockMultiThreaded(blockMemory)
        }
    }

    private fun fillMemoryBlockSingleThreaded(blockMemory: Array<LongArray>) {
        for (pass in 0 until iterations) {
            for (slice in 0 until ARGON2_SYNC_POINTS) {
                fillSegment(pass, 0, slice, blockMemory)
            }
        }
    }

    private suspend fun fillMemoryBlockMultiThreaded(blockMemory: Array<LongArray>) =
        coroutineScope {
            val deferredTasks = mutableListOf<Deferred<Unit>>()

            for (i in 0 until iterations) {
                for (j in 0 until ARGON2_SYNC_POINTS) {
                    for (k in 0 until parallelism) {
                        val task = async {
                            fillSegment(
                                i,
                                k,
                                j,
                                blockMemory
                            )
                        }

                        deferredTasks.add(task)
                    }

                    try {
                        for (task in deferredTasks) {
                            task.await()
                        }
                    } catch (e: Exception) {
                        clear(blockMemory)
                    }
                }
            }
        }

    private fun fillSegment(pass: Int, lane: Int, slice: Int, blockMemory: Array<LongArray>) {
        var addressBlock = LongArray(0)
        var inputBlock = LongArray(0)
        var zeroBlock = LongArray(0)

        val dataIndependentAddressing = isDataIndependentAddressing(pass, slice)
        val startingIndex = getStartingIndex(pass, slice)
        var currentOffset = lane * laneLength + slice * segmentLength + startingIndex
        var prevOffset = getPrevOffset(currentOffset)

        if (dataIndependentAddressing) {
            addressBlock = LongArray(ARGON2_QWORDS_IN_BLOCK)
            zeroBlock = LongArray(ARGON2_QWORDS_IN_BLOCK)
            inputBlock = LongArray(ARGON2_QWORDS_IN_BLOCK)

            initAddressBlocks(pass, lane, slice, zeroBlock, inputBlock, addressBlock, blockMemory)
        }

        var i = startingIndex
        while (i < segmentLength) {
            prevOffset = rotatePrevOffset(currentOffset, prevOffset)

            val pseudoRandom = getPseudoRandom(
                i,
                addressBlock,
                inputBlock,
                zeroBlock,
                prevOffset,
                dataIndependentAddressing,
                blockMemory
            )
            val refLane = getRefLane(pass, lane, slice, pseudoRandom)
            val refColumn = getRefColumn(pass, slice, i, pseudoRandom, refLane == lane)

            val prevBlock = blockMemory[prevOffset]
            val refBlock = blockMemory[(laneLength) * refLane + refColumn]
            val currentBlock = blockMemory[currentOffset]

            val withXor = isWithXor(pass)
            fillBlock(prevBlock, refBlock, currentBlock, withXor)
            i++
            currentOffset++
            prevOffset++
        }
    }

    private fun isDataIndependentAddressing(pass: Int, slice: Int): Boolean {
        return (variant === Argon2Variant.I) || (variant === Argon2Variant.ID && (pass == 0) && (slice < ARGON2_SYNC_POINTS / 2))
    }

    private fun getPrevOffset(currentOffset: Int): Int {
        return if (currentOffset % laneLength == 0) {
            currentOffset + laneLength - 1
        } else {
            currentOffset - 1
        }
    }

    private fun rotatePrevOffset(currentOffset: Int, prevOffset: Int): Int {
        var result = prevOffset

        if (currentOffset % laneLength == 1) {
            result = currentOffset - 1
        }

        return result
    }

    private fun getPseudoRandom(
        index: Int,
        addressBlock: LongArray,
        inputBlock: LongArray,
        zeroBlock: LongArray,
        prevOffset: Int,
        dataIndependentAddressing: Boolean,
        blockMemory: Array<LongArray>
    ): Long {
        if (dataIndependentAddressing) {
            if (index % ARGON2_ADDRESSES_IN_BLOCK == 0) {
                nextAddresses(zeroBlock, inputBlock, addressBlock)
            }

            return addressBlock[index % ARGON2_ADDRESSES_IN_BLOCK]
        } else {
            return blockMemory[prevOffset][0]
        }
    }

    private fun getRefLane(pass: Int, lane: Int, slice: Int, pseudoRandom: Long): Int {
        var refLane = ((pseudoRandom ushr 32) % parallelism).toInt()

        if (pass == 0 && slice == 0) {
            refLane = lane
        }

        return refLane
    }

    private fun initAddressBlocks(
        pass: Int,
        lane: Int,
        slice: Int,
        zeroBlock: LongArray,
        inputBlock: LongArray,
        addressBlock: LongArray,
        blockMemory: Array<LongArray>
    ) {
        inputBlock[0] = intToLong(pass)
        inputBlock[1] = intToLong(lane)
        inputBlock[2] = intToLong(slice)
        inputBlock[3] = intToLong(blockMemory.size)
        inputBlock[4] = intToLong(iterations)
        inputBlock[5] = intToLong(variant.ordinal)

        if (pass == 0 && slice == 0) {
            nextAddresses(zeroBlock, inputBlock, addressBlock)
        }
    }

    private fun getRefColumn(
        pass: Int,
        slice: Int,
        index: Int,
        pseudoRandom: Long,
        sameLane: Boolean
    ): Int {
        val referenceAreaSize: Int
        val startPosition: Int

        if (pass == 0) {
            startPosition = 0

            referenceAreaSize = if (sameLane) {
                slice * segmentLength + index - 1
            } else {
                slice * segmentLength + (if ((index == 0)) (-1) else 0)
            }
        } else {
            startPosition = ((slice + 1) * segmentLength) % laneLength

            referenceAreaSize = if (sameLane) {
                laneLength - segmentLength + index - 1
            } else {
                laneLength - segmentLength + (if ((index == 0)) (-1) else 0)
            }
        }

        var relativePosition = pseudoRandom and 0xFFFFFFFFL

        relativePosition = (relativePosition * relativePosition) ushr 32
        relativePosition = referenceAreaSize - 1 - (referenceAreaSize * relativePosition ushr 32)

        return (startPosition + relativePosition).toInt() % laneLength
    }

    private fun isWithXor(pass: Int): Boolean {
        return !(pass == 0 || version == ARGON2_VERSION_10)
    }

    private fun ending(blockMemory: Array<LongArray>): ByteArray {
        val finalBlock = blockMemory[laneLength - 1]

        for (i in 1 until parallelism) {
            val lastBlockInLane = i * laneLength + (laneLength - 1)
            xor(finalBlock, blockMemory[lastBlockInLane])
        }

        val finalBlockBytes = ByteArray(ARGON2_BLOCK_SIZE)

        for (i in finalBlock.indices) {
            val bytes: ByteArray = longToLittleEndian(finalBlock[i])
            arraycopy(bytes, 0, finalBlockBytes, i * bytes.size, bytes.size)
        }

        val finalResult = blake2bLong(finalBlockBytes, outputLength)

        clear(blockMemory)

        return finalResult
    }

    private fun clear(blockMemory: Array<LongArray>) {
        for (block in blockMemory) {
            block.fill(0)
        }
    }

    private fun copyOf(old: Array<LongArray>): Array<LongArray> {
        val current = Array(old.size) {
            LongArray(
                ARGON2_QWORDS_IN_BLOCK
            )
        }

        for (i in old.indices) {
            arraycopy(current[i], 0, old[i], 0, ARGON2_QWORDS_IN_BLOCK)
        }

        return current
    }

    companion object {

        const val ARGON2_VERSION_10: Int = 0x10

        const val ARGON2_VERSION_13: Int = 0x13

        const val ARGON2_INITIAL_DIGEST_LENGTH: Int = 64

        const val ARGON2_ADDRESSES_IN_BLOCK: Int = 128

        private const val ARGON2_SYNC_POINTS = 4

        private const val ARGON2_INITIAL_SEED_LENGTH = 72

        private const val ARGON2_BLOCK_SIZE = 1024

        const val ARGON2_QWORDS_IN_BLOCK: Int = ARGON2_BLOCK_SIZE / 8

        private fun getInitialHashLong(initialHash: ByteArray, appendix: ByteArray): ByteArray {
            val initialHashLong = ByteArray(ARGON2_INITIAL_SEED_LENGTH)

            arraycopy(
                initialHash,
                0,
                initialHashLong,
                0,
                ARGON2_INITIAL_DIGEST_LENGTH
            )

            arraycopy(
                appendix,
                0,
                initialHashLong,
                ARGON2_INITIAL_DIGEST_LENGTH,
                4
            )

            return initialHashLong
        }

        private fun updateWithLength(blake2b: Blake2b, input: ByteArray?) {
            if (input != null) {
                blake2b.update(intToLittleEndian(input.size))
                blake2b.update(input)
            } else {
                blake2b.update(intToLittleEndian(0))
            }
        }

        private fun getStartingIndex(pass: Int, slice: Int): Int {
            return if ((pass == 0) && (slice == 0)) {
                2
            } else {
                0
            }
        }

        private fun nextAddresses(
            zeroBlock: LongArray,
            inputBlock: LongArray,
            addressBlock: LongArray
        ) {
            inputBlock[6]++
            fillBlock(zeroBlock, inputBlock, addressBlock, false)
            fillBlock(zeroBlock, addressBlock, addressBlock, false)
        }

        private fun fillBlock(
            x: LongArray,
            y: LongArray,
            currentBlock: LongArray,
            withXor: Boolean
        ) {
            val r = LongArray(ARGON2_QWORDS_IN_BLOCK)
            val z = LongArray(ARGON2_QWORDS_IN_BLOCK)

            xor(r, x, y)
            arraycopy(r, 0, z, 0, z.size)

            for (i in 0..7) {
                roundFunction(
                    z,
                    16 * i,
                    16 * i + 1,
                    16 * i + 2,
                    16 * i + 3,
                    16 * i + 4,
                    16 * i + 5,
                    16 * i + 6,
                    16 * i + 7,
                    16 * i + 8,
                    16 * i + 9,
                    16 * i + 10,
                    16 * i + 11,
                    16 * i + 12,
                    16 * i + 13,
                    16 * i + 14,
                    16 * i + 15
                )
            }

            for (i in 0..7) {
                roundFunction(
                    z,
                    2 * i,
                    2 * i + 1,
                    2 * i + 16,
                    2 * i + 17,
                    2 * i + 32,
                    2 * i + 33,
                    2 * i + 48,
                    2 * i + 49,
                    2 * i + 64,
                    2 * i + 65,
                    2 * i + 80,
                    2 * i + 81,
                    2 * i + 96,
                    2 * i + 97,
                    2 * i + 112,
                    2 * i + 113
                )
            }

            if (withXor) {
                xor(currentBlock, r, z, currentBlock)
            } else {
                xor(currentBlock, r, z)
            }
        }

        private fun roundFunction(
            block: LongArray,
            v0: Int,
            v1: Int,
            v2: Int,
            v3: Int,
            v4: Int,
            v5: Int,
            v6: Int,
            v7: Int,
            v8: Int,
            v9: Int,  // NOSONAR
            v10: Int,
            v11: Int,
            v12: Int,
            v13: Int,
            v14: Int,
            v15: Int
        ) {
            f(block, v0, v4, v8, v12)
            f(block, v1, v5, v9, v13)
            f(block, v2, v6, v10, v14)
            f(block, v3, v7, v11, v15)

            f(block, v0, v5, v10, v15)
            f(block, v1, v6, v11, v12)
            f(block, v2, v7, v8, v13)
            f(block, v3, v4, v9, v14)
        }

        private fun f(block: LongArray, a: Int, b: Int, c: Int, d: Int) {
            fBlaMka(block, a, b)
            rotr64(block, d, a, 32)

            fBlaMka(block, c, d)
            rotr64(block, b, c, 24)

            fBlaMka(block, a, b)
            rotr64(block, d, a, 16)

            fBlaMka(block, c, d)
            rotr64(block, b, c, 63)
        }

        private fun fBlaMka(block: LongArray, x: Int, y: Int) {
            val m = 0xFFFFFFFFL
            val xy = (block[x] and m) * (block[y] and m)

            block[x] = block[x] + block[y] + 2 * xy
        }

        private fun rotr64(block: LongArray, v: Int, w: Int, c: Long) {
            val temp = block[v] xor block[w]
            block[v] = (temp ushr c.toInt()) or (temp shl (64 - c).toInt())
        }
    }
}
