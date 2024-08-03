package com.mooncloak.kodetools.argon2

import org.kotlincrypto.endians.LittleEndian
import org.kotlincrypto.endians.LittleEndian.Companion.toLittleEndian

internal fun longToLittleEndian(n: Long): ByteArray =
    n.toLittleEndian().toByteArray()

public fun intToLittleEndian(a: Int): ByteArray =
    a.toLittleEndian().toByteArray()

internal fun littleEndianToLong(bs: ByteArray, off: Int = 0): Long =
    LittleEndian.bytesToLong(
        bs[off],
        bs[off + 1],
        bs[off + 2],
        bs[off + 3],
        bs[off + 4],
        bs[off + 5],
        bs[off + 6],
        bs[off + 7]
    )

internal fun ByteArray.toLongArray(): LongArray {
    val v = LongArray(128)
    for (i in v.indices) {
        val slice: ByteArray = this.copyOfRange(i * 8, (i + 1) * 8)
        v[i] = littleEndianToLong(slice)
    }
    return v
}

internal fun intToLong(x: Int): Long {
    val intBytes = intToLittleEndian(x)
    val bytes = ByteArray(8)

    arraycopy(intBytes, 0, bytes, 0, 4)

    return littleEndianToLong(bytes)
}

internal fun xor(t: LongArray, b1: LongArray, b2: LongArray) {
    for (i in t.indices) {
        t[i] = b1[i] xor b2[i]
    }
}

internal fun xor(t: LongArray, b1: LongArray, b2: LongArray, b3: LongArray) {
    for (i in t.indices) {
        t[i] = b1[i] xor b2[i] xor b3[i]
    }
}

internal fun xor(t: LongArray, other: LongArray) {
    for (i in t.indices) {
        t[i] = t[i] xor other[i]
    }
}

internal fun arraycopy(
    source: LongArray,
    sourcePosition: Int,
    destination: LongArray,
    destinationPosition: Int,
    length: Int
) {
    source.copyInto(
        destination = destination,
        destinationOffset = destinationPosition,
        startIndex = sourcePosition,
        endIndex = sourcePosition + length
    )
}

internal fun arraycopy(
    source: ByteArray,
    sourcePosition: Int,
    destination: ByteArray,
    destinationPosition: Int,
    length: Int
) {
    source.copyInto(
        destination = destination,
        destinationOffset = destinationPosition,
        startIndex = sourcePosition,
        endIndex = sourcePosition + length
    )
}
