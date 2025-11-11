package com.sam.keystone.components

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.sam.keystone.dto.response.TokenResponseDto
import com.sam.keystone.entity.User
import com.sam.keystone.models.JWTTokenType
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.io.ResourceLoader
import org.springframework.stereotype.Component
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import kotlin.io.encoding.Base64
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.ExperimentalTime
import kotlin.time.toJavaInstant

@Component
class JWTTokenManager(
    private val resourceLoader: ResourceLoader,
) {

    @Value($$"${jwt.audience}")
    lateinit var jwtAudience: String

    @Value($$"${jwt.issuer}")
    lateinit var jwtIssuer: String

    @Value($$"${jwt.private-key-path}")
    lateinit var privateKeyPath: String

    @Value($$"${jwt.public-key-path}")
    lateinit var publicKeyPath: String

    @Value($$"${jwt.access-token-expiry-minutes}")
    lateinit var accessTokenLife: String

    @Value($$"${jwt.refresh-token-expiry-days}")
    lateinit var refreshTokenLife: String

    private val _algorithm: Algorithm by lazy {
        val publicKey = loadPublicKey(publicKeyPath)
        val privateKey = loadPrivateKey(privateKeyPath)
        Algorithm.RSA256(publicKey, privateKey)
    }

    fun generateTokenPairs(user: User): TokenResponseDto {

        val accessTokenDuration = (accessTokenLife).toInt().minutes
        val refreshTokenDuration = (refreshTokenLife).toInt().days

        return TokenResponseDto(
            accessToken = generateToken(user = user, duration = accessTokenDuration, type = JWTTokenType.ACCESS_TOKEN),
            refreshToken = generateToken(
                user = user,
                duration = refreshTokenDuration,
                type = JWTTokenType.REFRESH_TOKEN
            )
        )
    }

    fun validateToken(token: String, type: JWTTokenType = JWTTokenType.ACCESS_TOKEN): Int? {
        return try {
            val claims = JWT.require(_algorithm).build().verify(token).claims

            val userIdClaim = claims.getOrDefault(JWT_CLAIM_USER_ID, null)
            val typeClaim = claims.getOrDefault(JWT_CLAIM_TOKEN_TYPE, null)

            if (typeClaim.asString() == type.name) userIdClaim?.asInt() else null
        } catch (_: Exception) {
            null
        }
    }

    @OptIn(ExperimentalTime::class)
    private fun generateToken(user: User, duration: Duration, type: JWTTokenType = JWTTokenType.ACCESS_TOKEN): String {

        val now = Clock.System.now()
        val expiry = now.plus(duration)

        val tokenGenerated = JWT.create()
            .withAudience(jwtAudience)
            .withIssuer(jwtIssuer)
            .withClaim(JWT_CLAIM_USER_ID, user.id)
            .withClaim(JWT_CLAIM_USER_NAME, user.userName)
            .withClaim(JWT_CLAIM_TOKEN_TYPE, type.name)
            .withExpiresAt(expiry.toJavaInstant())
            .sign(_algorithm)

        return tokenGenerated
    }

    private fun decodeKeys(location: String, isPrivate: Boolean = true): ByteArray {
        val resource = resourceLoader.getResource(location)
        val keyText = resource.inputStream.bufferedReader().use { it.readText() }
        val type = if (isPrivate) "PRIVATE" else "PUBLIC"
        val cleaned = keyText
            .replace("-----BEGIN $type KEY-----", "")
            .replace("-----END $type KEY-----", "")
            .replace("\\s".toRegex(), "")
        return Base64.decode(cleaned)
    }


    private fun loadPublicKey(location: String): RSAPublicKey {
        val bytes = decodeKeys(location, false)
        val spec = X509EncodedKeySpec(bytes)
        return KeyFactory.getInstance("RSA")
            .generatePublic(spec) as RSAPublicKey
    }

    private fun loadPrivateKey(location: String): RSAPrivateKey {
        val bytes = decodeKeys(location, true)
        val spec = PKCS8EncodedKeySpec(bytes)
        return KeyFactory.getInstance("RSA")
            .generatePrivate(spec) as RSAPrivateKey
    }

    companion object {
        private const val JWT_CLAIM_USER_NAME = "user_name"
        private const val JWT_CLAIM_USER_ID = "user_id"
        private const val JWT_CLAIM_TOKEN_TYPE = "token_type"
    }
}