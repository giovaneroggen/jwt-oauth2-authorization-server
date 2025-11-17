package br.com.security.server.oauth2.jwt.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.core.io.FileSystemResource
import org.springframework.http.MediaType
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.crypto.encrypt.KeyStoreKeyFactory
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import java.util.*

@Configuration
@EnableMethodSecurity // habilita @PreAuthorize
class AuthorizationServerConfig {

    // --- PasswordEncoder global ---
    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    // --- JWT / JWK ---
    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyStoreResource = FileSystemResource("./certs/oauth2-keys.jks")
        val keyStorePassword = "changeit".toCharArray()
        val keyAlias = "oauth2-jwt-key"
        val keyPassword = "changeit".toCharArray()

        val keyStoreKeyFactory = KeyStoreKeyFactory(keyStoreResource, keyStorePassword)
        val keyPair = keyStoreKeyFactory.getKeyPair(keyAlias, keyPassword)

        val rsaKey = RSAKey.Builder(keyPair.public as java.security.interfaces.RSAPublicKey)
            .privateKey(keyPair.private as java.security.interfaces.RSAPrivateKey)
            .keyID(keyAlias)
            .build()

        val jwkSet = JWKSet(rsaKey)
        return JWKSource { selector, _ -> selector.select(jwkSet) }
    }

    // --- Registered client ---
    @Bean
    fun registeredClientRepository(passwordEncoder: PasswordEncoder): RegisteredClientRepository {
        val client = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("client-id")
            .clientSecret(passwordEncoder.encode("client-secret"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://localhost:8081/login/oauth2/code/client-id")
            .scope("openid")
            .scope("api") // scope para criar usuários via API
            .build()
        return InMemoryRegisteredClientRepository(client)
    }

    // --- Config padrão do Authorization Server ---
    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings =
        AuthorizationServerSettings.builder().build()


    @Bean
    @Order(1)
    @Throws(Exception::class)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        val authorizationServer = OAuth2AuthorizationServerConfigurer
            .authorizationServer()
            .oidc(Customizer.withDefaults())

        http.securityMatcher(authorizationServer.endpointsMatcher)
        http.with(authorizationServer, Customizer.withDefaults())
        http.authorizeHttpRequests{
            it.anyRequest().authenticated()
        }
        http.oauth2ResourceServer {
            it.jwt(Customizer.withDefaults())
        }
        http.exceptionHandling{
            it.defaultAuthenticationEntryPointFor(
                LoginUrlAuthenticationEntryPoint("/login"),
                createRequestMatcher()
            )
        }
        return http.build()
    }

    @Bean
    @Order(2)
    fun apiSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .securityMatcher("/api/**") // só aplica para rotas /api/**
            .authorizeHttpRequests { auth ->
                auth.anyRequest().authenticated() // exige token válido
            }
            .oauth2ResourceServer { oauth2 ->
                oauth2.jwt { jwt ->
                    jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())
                }
            }
        return http.build()
    }

    @Bean
    @Order(3)
    @Throws(Exception::class)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        http.authorizeHttpRequests{
            it.anyRequest().authenticated()
        }
            .formLogin(Customizer.withDefaults())
        return http.build()
    }

    @Bean
    fun jwtAuthenticationConverter(): JwtAuthenticationConverter {
        val converter = JwtAuthenticationConverter()

        converter.setJwtGrantedAuthoritiesConverter { jwt ->
            val authorities = mutableListOf<GrantedAuthority>()

            // 1. Adiciona SCOPES (padrão)
            val scopes = jwt.getClaimAsStringList("scope") ?: emptyList()
            authorities.addAll(scopes.map { SimpleGrantedAuthority("SCOPE_$it") })

            // 2. Adiciona ROLES do claim "roles"
            val roles = jwt.getClaimAsStringList("roles") ?: emptyList()
            authorities.addAll(roles.map { SimpleGrantedAuthority(it) })

            authorities
        }

        return converter
    }

    private fun createRequestMatcher(): RequestMatcher {
        val requestMatcher = MediaTypeRequestMatcher(MediaType.TEXT_HTML)
        requestMatcher.setIgnoredMediaTypes(setOf(MediaType.ALL))
        return requestMatcher
    }
}

