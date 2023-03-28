package com.example.springsecurity6.security.userdetails

import com.example.springsecurity6.user.UserRepository
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service

@Service
class UserDetailsServiceImpl(
    private val userRepository: UserRepository,
) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        val user = userRepository.findByUsername(username)
            ?: throw RuntimeException("There is no user where email: $username")

        return CustomUserDetails(user)
    }
}
