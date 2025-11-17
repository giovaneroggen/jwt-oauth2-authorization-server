package br.com.security.server.oauth2.jwt

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.security.web.FilterChainProxy


//@EnableWebSecurity
@SpringBootApplication
class AuthorizationServerApplication : CommandLineRunner {
    @Autowired
    private lateinit var filterChainProxy: FilterChainProxy

    override fun run(vararg args: String?) {

        println(filterChainProxy.filterChains)
    }

}

fun main(args: Array<String>) {
	runApplication<AuthorizationServerApplication>(*args)
}
