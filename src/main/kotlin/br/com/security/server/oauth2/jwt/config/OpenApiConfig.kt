package br.com.security.server.oauth2.jwt.config

import io.swagger.v3.oas.models.Components
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.Info
import io.swagger.v3.oas.models.security.SecurityRequirement
import io.swagger.v3.oas.models.security.SecurityScheme
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class OpenApiConfig {
    @Bean
    fun customOpenAPI(): OpenAPI? {
        val securitySchemeName = "bearerAuth"

        return OpenAPI()
            .info(
                Info()
                    .title("Jwt OAuth2 Authorization Server API")
                    .version("v1")
                    .description("API protegida via OAuth2 JWT")
            )
            .addSecurityItem(SecurityRequirement().addList(securitySchemeName))
//            .components(
//                Components()
//                    .addSecuritySchemes(
//                        securitySchemeName,
//                        SecurityScheme()
//                            .type(SecurityScheme.Type.HTTP)
//                            .scheme("bearer")
//                            .bearerFormat("JWT")
//                    )
//            )
    }
}
