package com.example.springsecurity6.security

import com.example.springsecurity6.user.UserRepository
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service

@Service
class JpaUserDetailsService(
    private val userRepository: UserRepository,
) : UserDetailsService {

    override fun loadUserByUsername(username: String): CustomUserDetails {
        val user = userRepository.findByUsername(username)
            ?: throw RuntimeException("There is no user where userName: $username")

        return CustomUserDetails(user)
    }
}