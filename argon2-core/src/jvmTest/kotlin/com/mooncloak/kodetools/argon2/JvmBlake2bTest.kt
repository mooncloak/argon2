package com.mooncloak.kodetools.argon2

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Before
import java.security.MessageDigest
import java.security.Security
import kotlin.test.Test

class JvmBlake2bTest {

    @Before
    fun init(){
        Security.addProvider(BouncyCastleProvider())
    }

    @Test
    fun testEmptyMessage() {
        val blake2b = Blake2b(64)
        val output = ByteArray(64)
        blake2b.doFinal(output, 0)

        val expected = MessageDigest.getInstance("BLAKE2B-512").digest()
        assertArrayEquals(expected, output)
    }

    @Test
    fun testShortMessage() {
        val message = "hello".toByteArray()
        val blake2b = Blake2b(64)
        blake2b.update(message)
        val output = ByteArray(64)
        blake2b.doFinal(output, 0)

        val expected = MessageDigest.getInstance("BLAKE2B-512").digest(message)
        assertArrayEquals(expected, output)
    }

    @Test
    fun testLongMessage() {
        val message = ByteArray(1024 * 1024) // 1 MB
        for (i in message.indices) {
            message[i] = i.toByte()
        }
        val blake2b = Blake2b(64)
        blake2b.update(message)
        val output = ByteArray(64)
        blake2b.doFinal(output, 0)

        val expected = MessageDigest.getInstance("BLAKE2B-512").digest(message)
        assertArrayEquals(expected, output)
    }

    @Test
    fun testOffsetAndLength() {
        val message = "helloworld".toByteArray()
        val blake2b = Blake2b(64)
        blake2b.update(message, 5, 5) // "world"
        val output = ByteArray(64)
        blake2b.doFinal(output, 0)

        val expected = MessageDigest.getInstance("BLAKE2B-512").digest("world".toByteArray())
        assertArrayEquals(expected, output)
    }

    @Test
    fun testMultipleUpdates() {
        val message1 = "hello".toByteArray()
        val message2 = "world".toByteArray()
        val blake2b = Blake2b(64)
        blake2b.update(message1)
        blake2b.update(message2)
        val output = ByteArray(64)
        blake2b.doFinal(output, 0)

        val expected = MessageDigest.getInstance("BLAKE2B-512").digest("helloworld".toByteArray())
        assertArrayEquals(expected, output)
    }

    @Test
    fun testReset() {
        val message1 = "hello".toByteArray()
        val message2 = "world".toByteArray()
        val blake2b = Blake2b(64)
        blake2b.update(message1)
        blake2b.reset()
        blake2b.update(message2)
        val output = ByteArray(64)
        blake2b.doFinal(output, 0)

        val expected = MessageDigest.getInstance("BLAKE2B-512").digest(message2)
        assertArrayEquals(expected, output)
    }
}
