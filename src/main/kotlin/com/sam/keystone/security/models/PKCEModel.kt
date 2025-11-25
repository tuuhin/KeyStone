package com.sam.keystone.security.models

import java.nio.charset.Charset
import java.security.MessageDigest
import kotlin.io.encoding.Base64

data class PKCEModel(
    val challengeCode: String,
    val challengeCodeAlgo: CodeChallengeMethods = CodeChallengeMethods.PLAIN,
) {

    private val algorithm by lazy {
        MessageDigest.getInstance("SHA-256").apply { reset() }
    }

    fun verifyHash(original: String, charset: Charset = Charsets.UTF_8): Boolean {
        if (original.isBlank()) return false

        val verifierCodeBytes = original.toByteArray(charset)
        val hashedResult = when (challengeCodeAlgo) {
            CodeChallengeMethods.PLAIN -> verifierCodeBytes
            CodeChallengeMethods.SHA_256 -> {
                algorithm.reset()
                algorithm.digest(verifierCodeBytes)
            }
        }
        val encodedResult = Base64.encode(hashedResult)

        return MessageDigest.isEqual(
            encodedResult.toByteArray(charset),
            challengeCode.toByteArray(charset)
        )
    }
}
