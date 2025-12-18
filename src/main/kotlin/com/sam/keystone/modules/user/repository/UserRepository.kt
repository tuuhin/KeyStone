package com.sam.keystone.modules.user.repository

import com.sam.keystone.modules.user.entity.User
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import org.springframework.stereotype.Repository

@Repository
interface UserRepository : JpaRepository<User, Long> {

    @Query(
        """
        SELECT u.id FROM User u 
        WHERE u.email = :email AND u.userName = :username
        """
    )
    fun findUserIDByEmailAndUsername(@Param("email") email: String, @Param("username") userName: String): Long?

    fun findUserByUserName(userName: String): User?

    fun findUserById(id: Long): User?
}