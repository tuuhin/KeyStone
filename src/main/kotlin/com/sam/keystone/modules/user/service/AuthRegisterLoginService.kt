package com.sam.keystone.modules.user.service

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.infrastructure.buckets.S3StorageBucket
import com.sam.keystone.infrastructure.email.EmailSenderService
import com.sam.keystone.infrastructure.jwt.JWTTokenGeneratorService
import com.sam.keystone.infrastructure.redis.MFASecretStore
import com.sam.keystone.infrastructure.redis.UserVerificationTokenManager
import com.sam.keystone.modules.user.dto.request.LoginUserRequest
import com.sam.keystone.modules.user.dto.request.RegisterUserRequest
import com.sam.keystone.modules.user.dto.response.LoginResponseDto
import com.sam.keystone.modules.user.dto.response.MFALoginResponseDto
import com.sam.keystone.modules.user.dto.response.RegisterUserResponseDto
import com.sam.keystone.modules.user.dto.response.UserResponseDto
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.entity.UserProfile
import com.sam.keystone.modules.user.entity.UserVerifyInfo
import com.sam.keystone.modules.user.exceptions.UserAuthException
import com.sam.keystone.modules.user.exceptions.UserValidationException
import com.sam.keystone.modules.user.exceptions.UserVerificationException
import com.sam.keystone.modules.user.repository.UserRepository
import com.sam.keystone.modules.user.utils.validator.PasswordValidator
import jakarta.transaction.Transactional
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import java.net.URLEncoder
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

@Service
class AuthRegisterLoginService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtTokenManager: JWTTokenGeneratorService,
    private val usersTokenManager: UserVerificationTokenManager,
    private val emailSender: EmailSenderService,
    private val tokenGenerator: RandomTokenGeneratorConfig,
    private val secretStore: MFASecretStore,
    private val bucket: S3StorageBucket,
    private val pWordValidator: PasswordValidator,
) {

    @Transactional
    fun createNewUser(request: RegisterUserRequest, validateStrength: Boolean = false): RegisterUserResponseDto {
        val probableUser = userRepository.findUserByUserName(request.userName)

        if (probableUser != null) throw UserValidationException("User name is already taken")
        if (validateStrength) pWordValidator.validate(request.password)

        val hash = passwordEncoder.encode(request.password)

        // create a new token
        val randomToken = tokenGenerator.generateRandomToken()
        val tokenHash = tokenGenerator.hashToken(randomToken)

        val newUser = User(
            email = request.email,
            pWordHash = hash,
            userName = request.userName,
        ).apply {
            profile = UserProfile(user = this)
            verifyState = UserVerifyInfo(user = this, isVerified = false, resendKey = tokenHash, isKeyValid = true)
        }

        val user = userRepository.save(newUser)
        // user created
        val verificationToken = usersTokenManager.createVerificationToken(user.id)
        val encodedToken = URLEncoder.encode(verificationToken, Charsets.UTF_8)
        emailSender.sendUserVerificationEmail(user, encodedToken)
        return RegisterUserResponseDto(user = user.currentUserProfile(), resendToken = randomToken)
    }


    @Transactional
    fun loginUser(
        request: LoginUserRequest,
        createRefreshToken: Boolean = true,
        accessTokenTTL: Duration? = null,
    ): LoginResponseDto {
        val user = userRepository.findUserByUserName(request.userName)
            ?: throw UserAuthException("Cannot find the given user")

        val passwordSame = passwordEncoder.matches(request.password, user.pWordHash)
        if (!passwordSame) throw UserAuthException("Invalid password")

        // user is not verified
        if (user.verifyState?.isVerified == false)
            throw UserVerificationException("User not verified")

        // in case totp is not added or enabled
        if (user.totpState == null || user.totpState?.isEnabled == false) {
            val tokens = jwtTokenManager.generateTokenPairs(
                user = user,
                accessTokenExpiry = accessTokenTTL,
                createRefreshToken = createRefreshToken
            )
            return LoginResponseDto.LoginResponseWithTokens(tokens)
        }
        // totp is added and is enabled
        val tokenValidity = 1.minutes
        val secret = tokenGenerator.generateRandomToken(byteLength = 12)
        val hashedSecret = tokenGenerator.hashToken(secret)
        secretStore.saveTempMFALoginToken(hashedSecret, user.id, tokenValidity)

        val mfaResponse = MFALoginResponseDto(isEnabled = true, token = secret, tokenValidity = tokenValidity)
        return LoginResponseDto.LoginResponseWith2Fa(mfaResponse)
    }

    @Transactional
    fun deleteUser(user: User) {
        val user = userRepository.findUserById(user.id) ?: throw UserAuthException("User cannot be deleted")
        userRepository.delete(user)
    }

    private fun User.currentUserProfile(): UserResponseDto {
        return UserResponseDto(
            id = id,
            userName = userName,
            email = email,
            isVerified = verifyState?.isVerified ?: false,
            createdAt = createdAt,
            updatedAt = updatedAt,
            bio = profile?.bio,
            avatarUrl = profile?.imageKey?.let { key -> bucket.provideSignedURL(key, 1.hours) },
            fullName = profile?.displayName,
        )
    }

}