package br.com.security.server.oauth2.jwt.service

import br.com.security.server.oauth2.jwt.repository.CustomerRepository
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.springframework.security.core.userdetails.User as SecurityUser

@Service
class CustomUserDetailsService(
    private val customerRepository: CustomerRepository
) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        val user = customerRepository.findByUsername(username)
            ?: throw UsernameNotFoundException("User not found: $username")

        return SecurityUser(
            user.username,
            user.password,
            listOf(org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"))
        )
    }
}