package br.com.security.server.oauth2.jwt.controller

import br.com.security.server.oauth2.jwt.entity.User
import br.com.security.server.oauth2.jwt.repository.UserRepository
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.*
import org.springframework.security.access.prepost.PreAuthorize

@RestController
@RequestMapping("/api/users")
class UserController(
    private val repository: UserRepository,
    private val passwordEncoder: PasswordEncoder
) {

    data class CreateUserRequest(
        val username: String,
        val password: String,
        val roles: List<String>
    )

    @PreAuthorize("hasAuthority('SCOPE_api') and hasRole('ADMIN')")
    @PostMapping
    fun createUser(@RequestBody request: CreateUserRequest): ResponseEntity<String> {
        if (repository.findByUsername(request.username) != null) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Usuário já existe")
        }

        val user = User(
            username = request.username,
            password = passwordEncoder.encode(request.password),
            roles = request.roles
        )

        repository.save(user)
        return ResponseEntity.status(HttpStatus.CREATED).body("Usuário criado com sucesso")
    }
}
