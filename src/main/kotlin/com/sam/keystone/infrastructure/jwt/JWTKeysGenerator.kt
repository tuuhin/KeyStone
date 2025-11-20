package com.sam.keystone.infrastructure.jwt

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.io.ResourceLoader
import org.springframework.stereotype.Component
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.*
import kotlin.io.encoding.Base64
import kotlin.time.*

@Component
class JWTKeysGenerator(
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


    private val _algorithm: Algorithm by lazy {
        val publicKey = loadPublicKey(publicKeyPath)
        val privateKey = loadPrivateKey(privateKeyPath)
        Algorithm.RSA256(publicKey, privateKey)
    }


    @OptIn(ExperimentalTime::class)
    fun validateToken(token: String): JWTValidationResult {
        val decoded = JWT.require(_algorithm).build().verify(token)
        val expireDuration = decoded.expiresAtAsInstant.toKotlinInstant() - Clock.System.now()

        if (expireDuration.isNegative()) throw JWTExpiredException()

        return JWTValidationResult(claims = decoded.claims, tokenTTL = expireDuration)
    }

    @OptIn(ExperimentalTime::class)
    fun generateToken(timeToLive: Duration, claims: Map<String, Any> = emptyMap()): String {

        val now = Clock.System.now()
        val expiry = now.plus(timeToLive)

        val tokenGenerated = JWT.create()
            .withAudience(jwtAudience)
            .withIssuer(jwtIssuer)
            .withExpiresAt(expiry.toJavaInstant())

        for ((key, value) in claims) {
            when (value) {
                is Int -> tokenGenerated.withClaim(key, value)
                is Double -> tokenGenerated.withClaim(key, value)
                is Long -> tokenGenerated.withClaim(key, value)
                is String -> tokenGenerated.withClaim(key, value)
                is Date -> tokenGenerated.withClaim(key, value)
                is Instant -> tokenGenerated.withClaim(key, value)
                is List<*> -> tokenGenerated.withClaim(key, value)
                is Boolean -> tokenGenerated.withClaim(key, value)
            }
        }

        return tokenGenerated.sign(_algorithm)
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
}