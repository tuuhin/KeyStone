package com.sam.keystone.modules.user.service

import com.sam.keystone.infrastructure.jwt.JWTTokenGeneratorService
import com.sam.keystone.infrastructure.redis.TokenBlackListManager
import com.sam.keystone.modules.user.dto.request.RefreshTokenRequest
import com.sam.keystone.modules.user.dto.response.TokenResponseDto
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.exceptions.UserAuthException
import com.sam.keystone.modules.user.models.JWTTokenType
import com.sam.keystone.modules.user.repository.UserRepository
import org.springframework.stereotype.Service

@Service
class AuthTokenManagementService(
    private val userRepository: UserRepository,
    private val jwtTokenManager: JWTTokenGeneratorService,
    private val blackListManager: TokenBlackListManager,
) {

    fun handleRefreshTokenRequest(request: RefreshTokenRequest, currentUser: User): TokenResponseDto {
        val result = jwtTokenManager.validateAndReturnAuthResult(request.token)
            ?: throw UserAuthException("Refresh Token expired or invalid")

        // check validation
        if (result.userId != currentUser.id) throw UserAuthException("Invalid account access request")
        val user = userRepository.findUserById(result.userId)
            ?: throw UserAuthException("Invalid account access request")

        if (blackListManager.isBlackListed(request.token))
            throw UserAuthException("Refresh token blacklisted")

        // add the item to the blacklist so it cannot be used anymore
        blackListManager.addToBlackList(request.token, type = JWTTokenType.REFRESH_TOKEN, result.expiresAfter)
        // create a new token pair
        return jwtTokenManager.generateTokenPairs(user)
    }


    fun blackListToken(request: RefreshTokenRequest, user: User) {
        val result = jwtTokenManager.validateAndReturnAuthResult(request.token)
            ?: throw UserAuthException("Refresh Token expired or invalid")

        if (result.tokenType != JWTTokenType.REFRESH_TOKEN)
            throw UserAuthException("Invalid token type provided")

        if (result.userId != user.id)
            throw UserAuthException("Invalid authenticated user")

        // add the item to the blacklist so it cannot be used anymore
        if (blackListManager.isBlackListed(request.token)) return
        blackListManager.addToBlackList(request.token, type = JWTTokenType.REFRESH_TOKEN, expiry = result.expiresAfter)
    }
}