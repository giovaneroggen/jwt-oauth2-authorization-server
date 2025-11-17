package br.com.security.server.oauth2.jwt.config

import org.springframework.security.crypto.password.PasswordEncoder
import java.security.MessageDigest

class DataWeaveSha256PasswordEncoder : PasswordEncoder {

    override fun encode(rawPassword: CharSequence): String {
        val bytes = rawPassword.toString().toByteArray(Charsets.UTF_8)

        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(bytes)

        return digest.joinToString("") { "%02X".format(it) } // HEX maiúsculo
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String): Boolean {
        return encode(rawPassword) == encodedPassword
    }
}