package com.sam.keystone.modules.oauth2.repository

import com.sam.keystone.modules.oauth2.entity.OAuth2ClientEntity
import com.sam.keystone.modules.user.entity.User
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface OAuth2ClientRepository : JpaRepository<OAuth2ClientEntity, Int> {

    fun findOAuth2ClientEntitiesByUser(user: User): List<OAuth2ClientEntity>

    fun findOAuth2ClientEntityByClientId(clientId: String): OAuth2ClientEntity?

    fun findOAuth2ClientEntityByClientIdAndUser(clientId: String, user: User): OAuth2ClientEntity?

    fun existsOAuth2ClientEntityByClientId(clientId: String): Boolean
}