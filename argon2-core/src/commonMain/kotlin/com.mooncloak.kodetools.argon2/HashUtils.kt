package com.mooncloak.kodetools.argon2

internal fun longToLittleEndian(n: Long): ByteArray {
    val bs = ByteArray(8)
    longToLittleEndian(n, bs, 0)
    return bs
}

internal fun longToLittleEndian(n: Long, bs: ByteArray, off: Int) {
    intToLittleEndian((n and 0xffffffffL).toInt(), bs, off)
    intToLittleEndian((n ushr 32).toInt(), bs, off + 4)
}

internal fun intToLittleEndian(n: Int, bs: ByteArray, off: Int) {
    var offset = off
    bs[offset] = n.toByte()
    bs[++offset] = (n ushr 8).toByte()
    bs[++offset] = (n ushr 16).toByte()
    bs[++offset] = (n ushr 24).toByte()
}

public fun intToLittleEndianBytes(a: Int): ByteArray {
    val result = ByteArray(4)
    result[0] = (a and 0xFF).toByte()
    result[1] = ((a shr 8) and 0xFF).toByte()
    result[2] = ((a shr 16) and 0xFF).toByte()
    result[3] = ((a shr 24) and 0xFF).toByte()
    return result
}

internal fun littleEndianToLong(bs: ByteArray, off: Int): Long {
    val lo = littleEndianToInt(bs, off)
    val hi = littleEndianToInt(bs, off + 4)
    return ((hi.toLong() and 0xffffffffL) shl 32) or (lo.toLong() and 0xffffffffL)
}

internal fun littleEndianToInt(bs: ByteArray, off: Int): Int {
    var offset = off
    var n = bs[offset].toInt() and 0xff
    n = n or ((bs[++offset].toInt() and 0xff) shl 8)
    n = n or ((bs[++offset].toInt() and 0xff) shl 16)
    n = n or (bs[++offset].toInt() shl 24)
    return n
}

public fun fromBytesToLongs(input: ByteArray): LongArray {
    val v = LongArray(128)
    for (i in v.indices) {
        val slice: ByteArray = input.copyOfRange(i * 8, (i + 1) * 8)
        v[i] = littleEndianBytesToLong(slice)
    }
    return v
}

public fun intToLong(x: Int): Long {
    val intBytes = intToLittleEndianBytes(x)
    val bytes = ByteArray(8)

    arraycopy(intBytes, 0, bytes, 0, 4)

    return littleEndianBytesToLong(bytes)
}

public fun xor(t: LongArray, b1: LongArray, b2: LongArray) {
    for (i in t.indices) {
        t[i] = b1[i] xor b2[i]
    }
}

public fun xor(t: LongArray, b1: LongArray, b2: LongArray, b3: LongArray) {
    for (i in t.indices) {
        t[i] = b1[i] xor b2[i] xor b3[i]
    }
}

public fun xor(t: LongArray, other: LongArray) {
    for (i in t.indices) {
        t[i] = t[i] xor other[i]
    }
}

public fun longToLittleEndianBytes(a: Long): ByteArray {
    val result = ByteArray(8)
    result[0] = (a and 0xFFL).toByte()
    result[1] = ((a shr 8) and 0xFFL).toByte()
    result[2] = ((a shr 16) and 0xFFL).toByte()
    result[3] = ((a shr 24) and 0xFFL).toByte()
    result[4] = ((a shr 32) and 0xFFL).toByte()
    result[5] = ((a shr 40) and 0xFFL).toByte()
    result[6] = ((a shr 48) and 0xFFL).toByte()
    result[7] = ((a shr 56) and 0xFFL).toByte()
    return result
}

public fun littleEndianBytesToLong(b: ByteArray): Long {
    var result: Long = 0
    for (i in 7 downTo 0) {
        result = result shl 8
        result = result or (b[i].toInt() and 0xFF).toLong()
    }
    return result
}

internal fun <T> arraycopy(
    source: Array<T>,
    sourcePosition: Int,
    destination: Array<T>,
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

internal fun arraycopy(
    source: CharArray,
    sourcePosition: Int,
    destination: CharArray,
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

internal fun fromBytesToString(input: ByteArray): String =
    input.decodeToString()

internal fun fromCharSequenceToBytes(input: CharSequence?): ByteArray =
    input?.toString()?.encodeToByteArray() ?: ByteArray(0)

public fun append(cs1: CharSequence?, cs2: CharSequence?): CharSequence? {
    if (cs1.isNullOrEmpty()) {
        return cs2
    }

    if (cs2.isNullOrEmpty()) {
        return cs1
    }

    val charArray1: CharArray = fromCharSequenceToChars(cs1)
    val charArray2: CharArray = fromCharSequenceToChars(cs2)

    val result = CharArray(charArray1.size + charArray2.size)
    arraycopy(charArray1, 0, result, 0, charArray1.size)
    arraycopy(charArray2, 0, result, charArray1.size, charArray2.size)

    return result.concatToString()
}

internal fun fromCharSequenceToChars(charSequence: CharSequence?): CharArray {
    if (charSequence.isNullOrEmpty()) {
        return CharArray(0)
    }

    val result = CharArray(charSequence.length)

    for (i in charSequence.indices) {
        result[i] = charSequence[i]
    }

    return result
}
