package com.sam.keystone.modules.user.repository

import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.entity.UserProfile
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface UserProfileRepository : JpaRepository<UserProfile, Long> {

    fun findUserProfileByUser(user: User): UserProfile?
}