package br.com.security.server.oauth2.jwt.controller

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/customers")
class UserController(
) {

    @PreAuthorize("hasAuthority('SCOPE_api') and hasRole('USER')")
    @PostMapping
    fun createUser(): ResponseEntity<String> {
        return ResponseEntity.status(HttpStatus.CREATED).body("Usuário criado com sucesso")
    }
}
