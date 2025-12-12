package com.sam.keystone.config

import com.sam.keystone.config.models.CodeEncoding
import org.apache.commons.codec.binary.Base32
import org.springframework.stereotype.Component
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.io.encoding.Base64

@Component
class RandomTokenGeneratorConfig {

    private val _messageDigest by lazy { MessageDigest.getInstance("SHA-256").apply { reset() } }
    private val _secureRandom by lazy { SecureRandom() }
    private val _base32 by lazy { Base32() }

    fun generateRandomToken(byteLength: Int = 32, encoding: CodeEncoding = CodeEncoding.BASE_64): String {
        val randomBytes = ByteArray(byteLength)

        _secureRandom.nextBytes(randomBytes)
        return randomBytes.toOutputString(encoding)
    }

    fun hashToken(token: String, encoding: CodeEncoding = CodeEncoding.BASE_64): String {
        _messageDigest.reset()
        val hash = _messageDigest.digest(token.toByteArray())
        return hash.toOutputString(encoding)
    }

    private fun ByteArray.toOutputString(encoding: CodeEncoding): String {
        return when (encoding) {
            CodeEncoding.BASE_64 -> Base64.encode(this)
            CodeEncoding.BASE_32 -> _base32.encodeToString(this)
            CodeEncoding.HEX_LOWERCASE -> toHexString(HexFormat.Default)
            CodeEncoding.HEX_UPPERCASE -> toHexString(HexFormat.UpperCase)
        }
    }
}