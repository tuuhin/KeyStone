package com.sam.keystone.infrastructure.otpauth

import org.springframework.stereotype.Component
import java.security.SecureRandom

@Component
class BackupCodeGenerator {

    private val _random by lazy { SecureRandom() }

    private val entropy: String
        get() {
            val aToZ = (65..90).map { it.toChar() }.joinToString("")
            val digits = ('0'..'9').joinToString("")
            return aToZ + digits
        }

    fun generateBackUpCode(): String {
        return (1..8)
            .map { entropy[_random.nextInt(entropy.length)] }
            .joinToString("")
            .let { str -> str.substring(0, 4) + "-" + str.substring(4) }
    }
}