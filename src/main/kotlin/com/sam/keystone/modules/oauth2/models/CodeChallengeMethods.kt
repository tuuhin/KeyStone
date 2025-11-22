package com.sam.keystone.modules.oauth2.models

import java.nio.charset.Charset
import java.security.MessageDigest


enum class CodeChallengeMethods(val simpleName: String) {
    PLAIN("plain"),
    SHA_256("sha256");

    private val algorithm by lazy {
        MessageDigest.getInstance("SHA-256")
    }


    fun verifyHash(original: String, hash: String, charset: Charset = Charsets.UTF_8): Boolean {
        val hashedResult = when (this) {
            PLAIN -> original
            SHA_256 -> {
                val bytes = original.toByteArray(charset)
                val resultBytes = algorithm.digest(bytes)
                resultBytes.toHexString(format = HexFormat.UpperCase)
            }
        }
        return hash.uppercase() == hashedResult
    }

    companion object {
        fun fromString(algo: String): CodeChallengeMethods {
            return try {
                CodeChallengeMethods.valueOf(algo)
            } catch (_: IllegalArgumentException) {
                PLAIN
            }
        }
    }
}