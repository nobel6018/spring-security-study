package com.example.springsecurity6.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder

@Configuration
class PasswordEncoders {

    @Bean
    fun bCryptPasswordEncoder(): BCryptPasswordEncoder {
        return BCryptPasswordEncoder()
    }

    @Bean
    fun sCryptPasswordEncoder(): SCryptPasswordEncoder {
        return SCryptPasswordEncoder(16384, 8, 1, 32, 64)
    }
}