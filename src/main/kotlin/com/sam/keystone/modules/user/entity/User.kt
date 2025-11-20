package com.sam.keystone.modules.user.entity

import com.sam.keystone.modules.user.models.UserRole
import jakarta.persistence.*
import java.time.Instant


@Entity
@Table(
    name = "users_table",
    indexes = [Index(name = "user_name", unique = true, columnList = "user_name")]
)
class User(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id", columnDefinition = "INTEGER")
    var id: Long = 0L,

    @Column(name = "email", nullable = false)
    val email: String = "",

    @Column(name = "p_word", nullable = false)
    var pWordHash: String = "",

    @Column(name = "user_name", nullable = false, unique = true)
    var userName: String = "",

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),

    @Column(name = "role", nullable = false)
    @Enumerated(value = EnumType.STRING)
    val role: UserRole = UserRole.USER,

    @OneToOne(mappedBy = "user", cascade = [CascadeType.ALL], optional = false)
    var profile: UserProfile? = null,

    @OneToOne(mappedBy = "user", cascade = [CascadeType.ALL], optional = false)
    var verifyState: UserVerifyInfo? = null,
)
