package com.sam.keystone.infrastructure.email

import com.sam.keystone.config.AppPropertiesConfig
import com.sam.keystone.modules.user.entity.User
import io.pebbletemplates.pebble.PebbleEngine
import org.springframework.scheduling.annotation.Async
import org.springframework.stereotype.Component
import java.io.StringWriter
import java.util.concurrent.CompletableFuture

@Component
class EmailSenderService(
    private val emailSender: EmailSender,
    private val pebbleEngine: PebbleEngine,
    private val appConfig: AppPropertiesConfig,
) {

    @Async
    fun sendUserVerificationEmail(
        user: User,
        verificationToken: String,
    ): CompletableFuture<Boolean> {

        val subject = "Verify Your Email - Keystone"
        val verifyLink = "${appConfig.emailVerifyRedirect}?token=${verificationToken}"

        // Prepare template context
        val template = pebbleEngine.getTemplate("verify_email")
        val context = mapOf(
            "user_name" to user.userName,
            "verify_link" to verifyLink
        )
        val writer = StringWriter()
        template.evaluate(writer, context)
        val htmlContent = writer.toString()

        return emailSender.sendEmail(title = subject, content = htmlContent, recipient = user.email)
    }
}