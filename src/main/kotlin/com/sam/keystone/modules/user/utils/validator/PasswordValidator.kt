package com.sam.keystone.modules.user.utils.validator

import com.sam.keystone.modules.user.exceptions.WeakPasswordException
import org.springframework.stereotype.Component
import kotlin.math.log2

@Component
class PasswordValidator {

    fun validate(password: String) {
        if (password.length < MIN_LENGTH) {
            throw WeakPasswordException("Password must be at least $MIN_LENGTH characters long")
        }
        val charsetSize = estimateCharsetSize(password)
        val entropy = calculateEntropy(password.length, charsetSize)

        if (entropy < MIN_ENTROPY_BITS) {
            throw WeakPasswordException(
                "Password is too weak (entropy %.1f bits, required %.1f bits)"
                    .format(entropy, MIN_ENTROPY_BITS)
            )
        }
        val lower = password.lowercase()

        if (lower.contains("password") ||
            lower.contains("admin") ||
            lower.contains("qwerty")
        ) {
            throw WeakPasswordException("Password contains common words")
        }
    }


    private fun estimateCharsetSize(password: String): Int {
        var size = 0

        if (password.any { it.isLowerCase() }) size += 26
        if (password.any { it.isUpperCase() }) size += 26
        if (password.any { it.isDigit() }) size += 10
        if (password.any { it in SYMBOLS }) size += SYMBOLS.length

        return size
    }

    private fun calculateEntropy(length: Int, charsetSize: Int): Double {
        return length * log2(charsetSize.toDouble())
    }

    companion object {
        private const val SYMBOLS = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~"
        private const val MIN_LENGTH: Int = 12
        private const val MIN_ENTROPY_BITS: Double = 60.0
    }
}