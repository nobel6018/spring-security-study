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
import org.springframework.web.filter.OncePerRequestFilter

class InitialAuthenticationFilter(
) : OncePerRequestFilter() {

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

        val a = UsernamePasswordAuthentication(username, password)
        manager.authenticate(a)

        val key = Keys.hmacShaKeyFor(signingKey.toByteArray())
        val jwt = Jwts.builder()
            .setClaims(mapOf("username" to username))
            .signWith(key)
            .compact()

        response.setHeader("Authorization", jwt)
    }

    override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        return !request.servletPath.equals("/v1/login")
    }
}
