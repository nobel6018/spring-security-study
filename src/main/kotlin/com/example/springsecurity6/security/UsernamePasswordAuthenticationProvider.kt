package com.example.springsecurity6.security

import com.example.springsecurity6.security.userdetails.UserDetailsServiceImpl
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Component

@Component
class UsernamePasswordAuthenticationProvider(
    private val userDetailsService: UserDetailsServiceImpl,
    private val bCryptPasswordEncoder: BCryptPasswordEncoder,
) : AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication {
        val username = authentication.name
        val password = authentication.credentials.toString()

        // AuthenticationProvider에서 구현해야하는 거는 다음 두 개
        // 1. UserDetailsService로 UserDetails 가져오고
        // 2. Password Encoder로 비밀번호 확인한다
        val userDetails = userDetailsService.loadUserByUsername(username)

        if (!bCryptPasswordEncoder.matches(password, userDetails.password)) {
            throw BadCredentialsException("Email or password are not correct")
        }

        return UsernamePasswordAuthentication(username, password)
    }

    override fun supports(authentication: Class<*>): Boolean {
        return UsernamePasswordAuthentication::class.java.isAssignableFrom(authentication)
    }
}
