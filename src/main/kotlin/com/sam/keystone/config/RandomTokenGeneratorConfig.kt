package com.sam.keystone.config

import com.sam.keystone.config.models.CodeEncoding
import org.springframework.stereotype.Component
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.io.encoding.Base64

@Component
class RandomTokenGeneratorConfig {

    private val _messageDigest by lazy { MessageDigest.getInstance("SHA-256").apply { reset() } }
    private val _secureRandom by lazy { SecureRandom() }

    fun generateRandomToken(byteLength: Int = 32, encoding: CodeEncoding = CodeEncoding.BASE_64): String {
        val randomBytes = ByteArray(byteLength)

        _secureRandom.nextBytes(randomBytes)
        return when (encoding) {
            CodeEncoding.BASE_64 -> Base64.encode(randomBytes)
            CodeEncoding.HEX_UPPERCASE -> randomBytes.toHexString(HexFormat.UpperCase)
            CodeEncoding.HEX_LOWERCASE -> randomBytes.toHexString(HexFormat.Default)
        }
    }

    fun hashToken(token: String, encoding: CodeEncoding = CodeEncoding.BASE_64): String {
        _messageDigest.reset()
        val hash = _messageDigest.digest(token.toByteArray())
        return when (encoding) {
            CodeEncoding.BASE_64 -> Base64.encode(hash)
            CodeEncoding.HEX_UPPERCASE -> hash.toHexString(HexFormat.UpperCase)
            CodeEncoding.HEX_LOWERCASE -> hash.toHexString(HexFormat.Default)
        }
    }
}