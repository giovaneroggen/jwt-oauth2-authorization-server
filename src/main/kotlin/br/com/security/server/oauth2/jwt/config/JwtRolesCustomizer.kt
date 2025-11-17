package br.com.security.server.oauth2.jwt.config

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.stereotype.Component

@Component
class JwtRolesCustomizer : OAuth2TokenCustomizer<JwtEncodingContext> {

    override fun customize(context: JwtEncodingContext) {
        if (context.tokenType.value == "access_token") {
            val authorities = context.getPrincipal<Authentication>().authorities.map { it.authority }
            context.claims.claim("roles", authorities)
        }
    }
}