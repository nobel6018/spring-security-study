package com.example.springsecurity6.config

import com.example.springsecurity6.security.filter.InitialAuthenticationFilter
import com.example.springsecurity6.security.filter.JwtAuthenticationFilter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter


@Configuration
@EnableWebSecurity
class ProjectConfig {

    @Bean
    fun initialAuthenticationFilter() = InitialAuthenticationFilter()

    @Bean
    fun jwtAuthenticationFilter() = JwtAuthenticationFilter()

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http.csrf().disable()
            .addFilterAt(initialAuthenticationFilter(), BasicAuthenticationFilter::class.java)
            .addFilterAfter(jwtAuthenticationFilter(), BasicAuthenticationFilter::class.java)
            .authorizeHttpRequests()
            .anyRequest().authenticated()

        return http.build()
    }

    @Bean
    fun authenticationManager(authenticationConfiguration: AuthenticationConfiguration): AuthenticationManager {
        return authenticationConfiguration.authenticationManager
    }
}
