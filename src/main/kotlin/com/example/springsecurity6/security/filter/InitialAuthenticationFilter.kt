package com.example.springsecurity6.security.filter

import com.example.springsecurity6.security.UsernamePasswordAuthentication
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.web.filter.OncePerRequestFilter

class InitialAuthenticationFilter : OncePerRequestFilter() {

    @Value("\${jwt.signing.key}")
    private lateinit var signingKey: String

    @Autowired
    private lateinit var manager: AuthenticationManager

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        val username = request.getHeader("username")
        val password = request.getHeader("password")

        var authentication: Authentication = UsernamePasswordAuthentication(username, password)
        authentication = manager.authenticate(authentication)

        val key = Keys.hmacShaKeyFor(signingKey.toByteArray())

        val after15MinInSec = (System.currentTimeMillis() / 1000) + 900
        val authorities = authentication.authorities.map { it.authority }
        val jwt = Jwts.builder()
            .addClaims(mapOf("type" to "accessToken"))
            .addClaims(mapOf("username" to username))
            .addClaims(mapOf("role" to "user"))
            .addClaims(mapOf("authorities" to authorities))
            .addClaims(mapOf("exp" to after15MinInSec))
            .signWith(key)
            .compact()

        val after2WeeksInSec = (System.currentTimeMillis() / 1000) + 1_209_600
        val refreshToken = Jwts.builder()
            .addClaims(mapOf("type" to "refreshToken"))
            .addClaims(mapOf("username" to username))
            .addClaims(mapOf("role" to "user"))
            .addClaims(mapOf("exp" to after2WeeksInSec))
            .signWith(key)
            .compact()

        response.setHeader("AccessToken", jwt)
        response.addHeader("RefreshToken", refreshToken)
    }

    override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        return !request.servletPath.equals("/v1/login")
    }
}
