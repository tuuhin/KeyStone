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
        val (userId, expireAfter) = jwtTokenManager.validateToken(request.token, type = JWTTokenType.REFRESH_TOKEN)
            ?: throw UserAuthException("Refresh Token expired or invalid")

        if (userId != currentUser.id) throw UserAuthException("Invalid account access request")

        if (blackListManager.isBlackListed(request.token))
            throw UserAuthException("Refresh token blacklisted")

        // add the item to the blacklist so it cannot be used anymore
        blackListManager.addToBlackList(request.token, type = JWTTokenType.REFRESH_TOKEN, expireAfter)

        // create a new token pair
        val user = userRepository.findUserById(userId) ?: throw UserAuthException("Cannot find user")
        return jwtTokenManager.generateTokenPairs(user)
    }


    fun blackListToken(request: RefreshTokenRequest) {
        val (_, expireAfter) = jwtTokenManager.validateToken(request.token, type = JWTTokenType.REFRESH_TOKEN)
            ?: throw UserAuthException("Refresh Token expired or invalid")

        // add the item to the blacklist so it cannot be used anymore
        if (blackListManager.isBlackListed(request.token)) return
        blackListManager.addToBlackList(request.token, type = JWTTokenType.REFRESH_TOKEN, expireAfter)
    }
}