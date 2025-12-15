package com.sam.keystone.infrastructure.otpauth

import dev.samstevens.totp.code.DefaultCodeGenerator
import dev.samstevens.totp.code.DefaultCodeVerifier
import dev.samstevens.totp.time.SystemTimeProvider
import org.springframework.stereotype.Component

@Component
class TOTPValidator {

    private val verifier by lazy {
        val timeProvider = SystemTimeProvider()
        val codeGenerator = DefaultCodeGenerator()
        DefaultCodeVerifier(codeGenerator, timeProvider).apply {
            setAllowedTimePeriodDiscrepancy(2)
        }
    }

    fun validateTOTP(code: String, secretBase32: String): Boolean {
        return verifier.isValidCode(secretBase32, code)

    }
}