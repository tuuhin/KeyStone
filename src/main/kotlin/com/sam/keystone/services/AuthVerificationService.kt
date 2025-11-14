package com.sam.keystone.services

import com.sam.keystone.components.EmailManager
import com.sam.keystone.components.TokenGenerator
import com.sam.keystone.components.UsersTokenManager
import com.sam.keystone.dto.request.ResendEmailRequest
import com.sam.keystone.entity.User
import com.sam.keystone.exceptions.TooManyRequestException
import com.sam.keystone.exceptions.UserValidationException
import com.sam.keystone.exceptions.UserVerificationException
import com.sam.keystone.repository.UserRepository
import com.sam.keystone.repository.UserVerificationRepository
import jakarta.transaction.Transactional
import org.springframework.stereotype.Service

@Service
class AuthVerificationService(
    private val usersTokenManager: UsersTokenManager,
    private val userRepository: UserRepository,
    private val emailVerifyRepository: UserVerificationRepository,
    private val emailManager: EmailManager,
    private val tokenGenerator: TokenGenerator,
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
        emailManager.sendVerificationEmailHtml(user, verificationToken)
    }
}