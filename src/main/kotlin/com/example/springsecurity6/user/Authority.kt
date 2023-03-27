package com.example.springsecurity6.user

import jakarta.persistence.*

@Entity
class Authority(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,

    val name: String,

    @JoinColumn(name = "user_id")
    @ManyToOne
    val user: User,
)