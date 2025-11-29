package com.sam.keystone.infrastructure.redis

import com.sam.keystone.security.models.CodeChallengeMethods
import com.sam.keystone.security.models.PKCEModel
import org.slf4j.LoggerFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Component
class OAuth2CodePKCEStore(
    private val template: RedisTemplate<String, Any>,
) {

    private val _logger by lazy { LoggerFactory.getLogger(this::class.java) }

    @Transactional
    fun saveClientPKCE(clientId: String, pkCE: PKCEModel, expiry: Duration = 5.minutes) {
        val operation = template.opsForHash<String, String>()
        val coreKey = "$OAUTH2_CODE_CHALLENGES:$clientId"
        operation.put(coreKey, OAUTH2_CHALLENGES_KEY_VERIFIER_HASH, pkCE.challengeCode)
        operation.put(coreKey, OAUTH_2_CHALLENGES_KEY_VERIFIER_ALGO, pkCE.challengeCodeAlgo.simpleName)
        operation.expire(
            coreKey,
            expiry.toJavaDuration(),
            mutableListOf(OAUTH2_CHALLENGES_KEY_VERIFIER_HASH, OAUTH_2_CHALLENGES_KEY_VERIFIER_ALGO)
        )
        _logger.debug("SAVING CODE CHALLENGE FOR CLIENT ID :$clientId")
    }

    @Transactional
    fun deleteClientPKCE(clientId: String) {
        val operation = template.opsForHash<String, String>()
        val coreKey = "$OAUTH2_CODE_CHALLENGES:$clientId"
        operation.delete(coreKey, OAUTH2_CHALLENGES_KEY_VERIFIER_HASH)
        operation.delete(coreKey, OAUTH_2_CHALLENGES_KEY_VERIFIER_ALGO)
        _logger.debug("DELETING CODE CHALLENGE FOR CLIENT ID :$clientId")
    }

    @Transactional(readOnly = true)
    fun getCodeChallenges(clientId: String): PKCEModel? {
        val operation = template.opsForHash<String, String>()
        val coreKey = "$OAUTH2_CODE_CHALLENGES:$clientId"
        val verifierHash = operation.get(coreKey, OAUTH2_CHALLENGES_KEY_VERIFIER_HASH) ?: return null
        val verifierAlgo = operation.get(coreKey, OAUTH_2_CHALLENGES_KEY_VERIFIER_ALGO) ?: return null
        _logger.debug("READING CODE CHALLENGE FOR CLIENT ID :$clientId :$verifierHash $verifierAlgo")
        val algo = CodeChallengeMethods.fromString(verifierAlgo)
        return PKCEModel(challengeCode = verifierHash, challengeCodeAlgo = algo)
    }

    companion object {
        private const val OAUTH2_CODE_CHALLENGES = "oauth2:challenges"
        private const val OAUTH2_CHALLENGES_KEY_VERIFIER_HASH = "verifier_hash"
        private const val OAUTH_2_CHALLENGES_KEY_VERIFIER_ALGO = "verifier_algo"
    }
}