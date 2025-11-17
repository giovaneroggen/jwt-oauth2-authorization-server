package br.com.security.server.oauth2.jwt.entity

import jakarta.persistence.*

@Entity
@Table(name = "customer")
data class Customer(

    @Id
    @Column(name = "customer_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val customerId: Long? = null,

    @Column(nullable = false)
    val name: String,

    @Column(nullable = false, unique = true)
    val username: String,

    @Column(nullable = false)
    val password: String
)