package com.sam.keystone.infrastructure.redis

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Component
class OAuth2CodePKCEStore(
    private val template: StringRedisTemplate,
) {

    @Transactional
    fun saveClientPKCE(
        clientId: String,
        challengeCode: String,
        challengeCodeAlgo: String,
        expiry: Duration = 5.minutes,
    ) {
        val operation = template.opsForHash<String, String>()
        val coreKey = "$OAUTH2_CODE_CHALLENGES:$clientId"
        operation.put(coreKey, OAUTH2_CHALLENGES_KEY_VERIFIER_HASH, challengeCode)
        operation.put(coreKey, OAUTH_2_CHALLENGES_KEY_VERIFIER_ALGO, challengeCodeAlgo)
        operation.expire(
            coreKey,
            expiry.toJavaDuration(),
            mutableListOf(OAUTH2_CHALLENGES_KEY_VERIFIER_HASH, OAUTH_2_CHALLENGES_KEY_VERIFIER_ALGO)
        )
    }

    @Transactional
    fun deleteClientPKCE(clientId: String) {
        val operation = template.opsForHash<String, String>()
        operation.delete("$OAUTH2_CODE_CHALLENGES:$clientId", OAUTH2_CHALLENGES_KEY_VERIFIER_HASH)
        operation.delete("$OAUTH2_CODE_CHALLENGES:$clientId", OAUTH_2_CHALLENGES_KEY_VERIFIER_ALGO)
    }

    @Transactional(readOnly = true)
    fun getCodeChallenges(clientId: String): Pair<String, String> {
        val operation = template.opsForHash<String, String>()
        val coreKey = "$OAUTH2_CODE_CHALLENGES:$clientId"
        val verifierHash = operation.get(coreKey, OAUTH2_CHALLENGES_KEY_VERIFIER_HASH) ?: ""
        val verifierAlgo = operation.get(coreKey, OAUTH_2_CHALLENGES_KEY_VERIFIER_ALGO) ?: ""
        return verifierHash to verifierAlgo
    }

    companion object {
        private const val OAUTH2_CODE_CHALLENGES = "oauth2:challenges"
        private const val OAUTH2_CHALLENGES_KEY_VERIFIER_HASH = "verifier_hash"
        private const val OAUTH_2_CHALLENGES_KEY_VERIFIER_ALGO = "verifier_algo"
    }
}