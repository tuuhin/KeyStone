package com.sam.keystone.modules.user.service

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.infrastructure.email.EmailSenderService
import com.sam.keystone.infrastructure.jwt.JWTTokenGeneratorService
import com.sam.keystone.infrastructure.redis.UserVerificationTokenManager
import com.sam.keystone.modules.user.dto.request.LoginUserRequest
import com.sam.keystone.modules.user.dto.request.RegisterUserRequest
import com.sam.keystone.modules.user.dto.response.RegisterUserResponseDto
import com.sam.keystone.modules.user.dto.response.TokenResponseDto
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.entity.UserProfile
import com.sam.keystone.modules.user.entity.UserVerifyInfo
import com.sam.keystone.modules.user.exceptions.UserAuthException
import com.sam.keystone.modules.user.exceptions.UserValidationException
import com.sam.keystone.modules.user.exceptions.UserVerificationException
import com.sam.keystone.modules.user.repository.UserRepository
import com.sam.keystone.modules.user.utils.mappers.toReposeDTO
import jakarta.transaction.Transactional
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import java.net.URLEncoder

@Service
class AuthRegisterLoginService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtTokenManager: JWTTokenGeneratorService,
    private val usersTokenManager: UserVerificationTokenManager,
    private val emailSender: EmailSenderService,
    private val tokenGenerator: RandomTokenGeneratorConfig,
) {

    @Transactional
    fun createNewUser(request: RegisterUserRequest): RegisterUserResponseDto {
        val probableUser = userRepository.findUserByUserName(request.userName)

        if (probableUser != null) throw UserValidationException("User name is already taken")

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
        return RegisterUserResponseDto(user = user.toReposeDTO(), resendToken = randomToken)
    }


    @Transactional
    fun loginUser(request: LoginUserRequest): TokenResponseDto {

        val user = userRepository.findUserByUserName(request.userName)
        val foundUser = user ?: throw UserAuthException("Cannot find the given user")

        val passwordSame = passwordEncoder.matches(request.password, foundUser.pWordHash)
        if (!passwordSame) throw UserAuthException("Invalid password")

        // user is not verified
        if (user.verifyState?.isVerified == false)
            throw UserVerificationException("User not verified")

        // so the user exists
        return jwtTokenManager.generateTokenPairs(foundUser)
    }

    @Transactional
    fun deleteUser(userId: Long) {
        val user = userRepository.findUserById(userId) ?: throw UserAuthException("User cannot be deleted")
        userRepository.delete(user)
    }

}