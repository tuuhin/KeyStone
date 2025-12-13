package com.sam.keystone.modules.mfa.services

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.config.models.CodeEncoding
import com.sam.keystone.infrastructure.jwt.JWTTokenGeneratorService
import com.sam.keystone.infrastructure.otpauth.AESEncryptionLayer
import com.sam.keystone.infrastructure.otpauth.TOTPValidator
import com.sam.keystone.infrastructure.redis.MFASecretStore
import com.sam.keystone.modules.mfa.dto.VerifyLoginRequestDto
import com.sam.keystone.modules.mfa.exceptions.MFAInvalidLoginChallengeException
import com.sam.keystone.modules.mfa.exceptions.MFANotEnabledException
import com.sam.keystone.modules.mfa.exceptions.TOTPCodeInvalidException
import com.sam.keystone.modules.mfa.repository.TOTPBackupCodeRepository
import com.sam.keystone.modules.mfa.repository.TOTPRepository
import com.sam.keystone.modules.user.dto.response.TokenResponseDto
import com.sam.keystone.modules.user.exceptions.UserAuthException
import com.sam.keystone.modules.user.repository.UserRepository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class MFAVerifyLoginService(
    private val tokenGenerator: RandomTokenGeneratorConfig,
    private val secretStore: MFASecretStore,
    private val tokenValidator: TOTPValidator,
    private val jwtTokenManager: JWTTokenGeneratorService,
    private val encryptor: AESEncryptionLayer,
    private val totpRepository: TOTPRepository,
    private val userRepository: UserRepository,
    private val backupCodeRepository: TOTPBackupCodeRepository,
) {

    @Transactional
    fun verifyLogin(request: VerifyLoginRequestDto): TokenResponseDto {
        // verify the request
        val hashedToken = tokenGenerator.hashToken(request.token)

        // temp will token will be automatically deleted when fetched
        val userId = secretStore.getTempMFALoginChallenge(hashedToken)
            ?: throw MFAInvalidLoginChallengeException()

        val user = userRepository.findUserById(userId) ?: throw UserAuthException("User not found")

        val totp = totpRepository.findTOTPEntityByUser(user) ?: throw MFANotEnabledException()
        if (!totp.isEnabled) throw MFANotEnabledException()

        val secret = encryptor.decrypt(
            text = totp.totpSecret,
            inputEncoding = CodeEncoding.BASE_32,
            outputEncoding = CodeEncoding.BASE_32
        )

        // validate the given code
        val isValid = tokenValidator.validateTOTP(request.code, secret)
        val requestValidated = if (isValid) true
        else {
            val hash = tokenGenerator.hashToken(request.code, CodeEncoding.HEX_LOWERCASE)
            val foundCode = backupCodeRepository.findTOTPBackupCodesEntityByBackUpCodeAndTotp(hash, totp)
            val isUsedCode = (foundCode?.isUsed) ?: true
            if (foundCode != null && !isUsedCode) {
                // update is used to true
                foundCode.isUsed = true
                backupCodeRepository.save(foundCode)
            }
            foundCode != null && !isUsedCode
        }

        if (!requestValidated) throw TOTPCodeInvalidException()

        // a correct user
        return try {
            jwtTokenManager.generateTokenPairs(user = user)
        } finally {
            secretStore.deleteMFALoginChallenge(hashedToken)
        }
    }
}