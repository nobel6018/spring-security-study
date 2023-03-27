package com.example.springsecurity6.user

import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository : JpaRepository<User, Long> {

    fun findByUsername(userName: String): User?
}