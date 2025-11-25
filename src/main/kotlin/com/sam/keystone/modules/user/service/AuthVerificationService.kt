package com.sam.keystone.modules.user.service

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.infrastructure.email.EmailSenderService
import com.sam.keystone.infrastructure.redis.UserVerificationTokenManager
import com.sam.keystone.modules.user.dto.request.ResendEmailRequest
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.exceptions.UserValidationException
import com.sam.keystone.modules.user.exceptions.UserVerificationException
import com.sam.keystone.modules.user.repository.UserRepository
import com.sam.keystone.modules.user.repository.UserVerificationRepository
import com.sam.keystone.security.exception.TooManyRequestException
import jakarta.transaction.Transactional
import org.springframework.stereotype.Service
import java.net.URLEncoder

@Service
class AuthVerificationService(
    private val usersTokenManager: UserVerificationTokenManager,
    private val userRepository: UserRepository,
    private val emailVerifyRepository: UserVerificationRepository,
    private val emailSender: EmailSenderService,
    private val tokenGenerator: RandomTokenGeneratorConfig,
) {

    @Transactional
    fun verifyRegisterToken(token: String): User {
        val userId = usersTokenManager.validateVerificationToken(token, deleteWhenDone = true)
            ?: throw UserValidationException("Cannot verify the given token")

        val user = userRepository.findUserById(userId)
            ?: throw UserValidationException("Cannot find the associated user")

        if (user.verifyState?.isVerified == true) throw UserVerificationException("User is already verified")

        val updatedUser = user.apply {
            verifyState?.isVerified = true
            verifyState?.isKeyValid = false
        }
        return userRepository.save(updatedUser)
    }


    @Transactional
    fun resendEmail(request: ResendEmailRequest) {

        val tokenHash = tokenGenerator.hashToken(request.resendKey)
        val verificationInfo = emailVerifyRepository.findUserVerifyInfoByResendKeyIs(tokenHash)

        val user = verificationInfo?.user ?: throw UserVerificationException("Cannot send mail 1")

        if (user.email != request.email) throw UserVerificationException("Cannot send mail")

        // so this is the correct user
        if (user.verifyState?.isVerified == true) throw UserVerificationException("User is already verified")

        if (usersTokenManager.isVerificationEmailLimitActive(user.id))
            throw TooManyRequestException("Cannot resend email this soon try later")
        // delete the earlier tokens
        usersTokenManager.deleteUserTokens(user.id)

        val verificationToken = usersTokenManager.createVerificationToken(user.id, setRateLimit = true)
        val encodedToken = URLEncoder.encode(verificationToken, Charsets.UTF_8)
        emailSender.sendUserVerificationEmail(user, encodedToken)
    }
}