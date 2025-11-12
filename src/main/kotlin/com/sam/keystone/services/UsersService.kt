package com.sam.keystone.services

import com.sam.keystone.components.JWTTokenManager
import com.sam.keystone.components.TokenBlackListManager
import com.sam.keystone.dto.request.LoginUserRequest
import com.sam.keystone.dto.request.RefreshTokenRequest
import com.sam.keystone.dto.request.RegisterUserRequest
import com.sam.keystone.dto.response.TokenResponseDto
import com.sam.keystone.entity.User
import com.sam.keystone.entity.UserProfile
import com.sam.keystone.exceptions.UserAuthException
import com.sam.keystone.exceptions.UserValidationException
import com.sam.keystone.models.JWTTokenType
import com.sam.keystone.repository.UserRepository
import jakarta.transaction.Transactional
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class UsersService(
    private val repository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val tokenManager: JWTTokenManager,
    private val blackListManager: TokenBlackListManager,
) {

    @Transactional
    fun createNewUser(request: RegisterUserRequest): TokenResponseDto {
        // check for errors
        if (repository.findUserByEmail(request.email) != null)
            throw UserValidationException("Email Id is already taken")

        if (repository.findUserByUserName(request.userName) != null)
            throw UserValidationException("User name is already taken")

        // now we can create a user
        val encoded = passwordEncoder.encode(request.password)

        val newUser = User(email = request.email, pWordHash = encoded, userName = request.userName)
        val newProfile = UserProfile(user = newUser)
        val userWithProfile = newUser.apply { profile = newProfile }

        val user = repository.save(userWithProfile)
        // so the user exists
        return tokenManager.generateTokenPairs(user)
    }


    @Transactional
    fun loginUser(request: LoginUserRequest): TokenResponseDto {

        if (request.email == null && request.userName == null)
            throw UserValidationException("Both username and email cannot be null")

        val user = if (request.email != null) repository.findUserByEmail(request.email)
        else repository.findUserByUserName(request.userName!!)

        val foundUser = user ?: throw UserAuthException("Cannot find the given user")

        val passwordSame = passwordEncoder.matches(request.password, foundUser.pWordHash)
        if (!passwordSame) throw UserAuthException("Invalid password")
        // so the user exists
        return tokenManager.generateTokenPairs(foundUser)
    }

    fun generateNewTokenPairs(request: RefreshTokenRequest, currentUser: User): TokenResponseDto {
        val (userId, expireAfter) = tokenManager.validateToken(request.token, type = JWTTokenType.REFRESH_TOKEN)
            ?: throw UserAuthException("Refresh Token expired or invalid")

        if (userId != currentUser.id) throw UserAuthException("Invalid account access request")

        if (blackListManager.isBlackListed(request.token))
            throw UserAuthException("Refresh token blacklisted")

        // add the item to the blacklist so it cannot be used anymore
        blackListManager.addToBlackList(request.token, expireAfter)

        // create a new token pair
        val user = repository.findUserById(userId) ?: throw UserAuthException("Cannot find user")
        return tokenManager.generateTokenPairs(user)
    }

    fun blackListToken(request: RefreshTokenRequest) {
        val (_, expireAfter) = tokenManager.validateToken(request.token, type = JWTTokenType.REFRESH_TOKEN)
            ?: throw UserAuthException("Refresh Token expired or invalid")

        // add the item to the blacklist so it cannot be used anymore
        if (blackListManager.isBlackListed(request.token)) return
        blackListManager.addToBlackList(request.token, expireAfter)
    }
}