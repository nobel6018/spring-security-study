package com.example.springsecurity6.security

import com.example.springsecurity6.user.ALGORITHM
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder
import org.springframework.stereotype.Service

@Service
class AuthenticationProviderService(
    private val userDetailsService: JpaUserDetailsService,
    private val bCryptPasswordEncoder: BCryptPasswordEncoder,
    private val sCryptPasswordEncoder: SCryptPasswordEncoder,
) : AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication {
        val username = authentication.name
        val password = authentication.credentials.toString()

        val user = userDetailsService.loadUserByUsername(username)

        return when (user.user.algorithm) {
            ALGORITHM.BCRYPT -> checkPassword(user, password, bCryptPasswordEncoder)
            ALGORITHM.SCRYPT -> checkPassword(user, password, sCryptPasswordEncoder)
        }
    }

    override fun supports(authentication: Class<*>): Boolean {
        return UsernamePasswordAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

    private fun checkPassword(
        user: CustomUserDetails,
        rawPassword: String,
        encoder: PasswordEncoder,
    ): UsernamePasswordAuthenticationToken {
        if (encoder.matches(rawPassword, user.password)) {
            return UsernamePasswordAuthenticationToken(user.user, user.password, user.authorities)
        } else {
            throw BadCredentialsException("Bad Credentials")
        }
    }
}