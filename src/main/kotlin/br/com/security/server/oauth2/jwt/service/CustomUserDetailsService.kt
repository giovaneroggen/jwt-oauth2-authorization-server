package br.com.security.server.oauth2.jwt.service

import br.com.security.server.oauth2.jwt.repository.UserRepository
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.springframework.security.core.userdetails.User as SecurityUser

@Service
class CustomUserDetailsService(
    private val userRepository: UserRepository
) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        val user = userRepository.findByUsername(username)
            ?: throw UsernameNotFoundException("User not found: $username")

        return SecurityUser(
            user.username,
            user.password,
            user.roles.map { org.springframework.security.core.authority.SimpleGrantedAuthority(it) }
        )
    }
}