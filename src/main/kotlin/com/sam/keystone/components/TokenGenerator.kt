package com.sam.keystone.components

import org.springframework.stereotype.Component
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.io.encoding.Base64

@Component
class TokenGenerator {

    private val messageDigest by lazy { MessageDigest.getInstance("SHA-256") }
    private val secureRandom by lazy { SecureRandom() }

    fun generateRandomToken(byteLength: Int = 32): String {
        val randomBytes = ByteArray(byteLength)

        secureRandom.nextBytes(randomBytes)
        return Base64.encode(randomBytes)
    }

    fun hashToken(token: String): String {
        val hash = messageDigest.digest(token.toByteArray())
        return Base64.encode(hash)
    }
}