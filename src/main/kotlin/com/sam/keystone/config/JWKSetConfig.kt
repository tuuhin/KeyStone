package com.sam.keystone.config

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.core.io.ResourceLoader
import org.springframework.stereotype.Component
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import kotlin.io.encoding.Base64

@Component
class JWKSetConfig(private val resourceLoader: ResourceLoader) {

    @Value($$"${jwt.public-key-path}")
    lateinit var publicKeyPath: String

    private fun decodeKeys(location: String): ByteArray {
        val resource = resourceLoader.getResource(location)
        val keyText = resource.inputStream.bufferedReader().use { it.readText() }
        val cleaned = keyText
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\\s".toRegex(), "")
        return Base64.decode(cleaned)
    }


    private fun loadPublicKey(location: String): RSAPublicKey {
        val bytes = decodeKeys(location)
        val spec = X509EncodedKeySpec(bytes)
        return KeyFactory.getInstance("RSA")
            .generatePublic(spec) as RSAPublicKey
    }

    @Bean
    fun makeJWKs(): JWKSet {
        val publicKey = loadPublicKey(publicKeyPath)
        val key = RSAKey.Builder(publicKey)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .keyID("b9ef0ae0-2777-411e-bf38-ac209181f7e6")
            .build()
        return JWKSet(key)
    }
}