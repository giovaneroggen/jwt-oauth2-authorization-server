package br.com.security.server.oauth2.jwt.repository

import br.com.security.server.oauth2.jwt.entity.Customer
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface CustomerRepository : JpaRepository<Customer, Long> {

    fun findByUsername(username: String): Customer?
}