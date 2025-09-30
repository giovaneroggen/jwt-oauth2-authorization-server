package br.com.security.server.oauth2.jwt.repository

import br.com.security.server.oauth2.jwt.entity.User
import org.springframework.data.mongodb.repository.MongoRepository

interface UserRepository : MongoRepository<User, String> {
    fun findByUsername(username: String): User?
}