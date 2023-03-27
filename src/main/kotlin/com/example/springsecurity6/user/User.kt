package com.example.springsecurity6.user

import jakarta.persistence.*

@Table(name = "users")
@Entity
class User(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,

    @Column(nullable = false)
    val username: String,

    @Column(nullable = false)
    val password: String,

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    val algorithm: ALGORITHM,

    @OneToMany(mappedBy = "user", fetch = FetchType.EAGER)
    val authorities: List<Authority> = mutableListOf(),
)

enum class ALGORITHM {
    BCRYPT, SCRYPT,
}