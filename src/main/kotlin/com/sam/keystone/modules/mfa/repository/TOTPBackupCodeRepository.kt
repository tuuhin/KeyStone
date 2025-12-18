package com.sam.keystone.modules.mfa.repository

import com.sam.keystone.modules.mfa.entity.TOTPBackupCodesEntity
import com.sam.keystone.modules.mfa.entity.TOTPEntity
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface TOTPBackupCodeRepository : JpaRepository<TOTPBackupCodesEntity, Long> {

    fun findTOTPBackupCodesEntitiesByTotp(totp: TOTPEntity): Set<TOTPBackupCodesEntity>

    fun findTOTPBackupCodesEntityByBackUpCodeAndTotp(backUpCode: String, totp: TOTPEntity): TOTPBackupCodesEntity?

    fun deleteTOTPBackupCodesEntityByTotp(totp: TOTPEntity)

}