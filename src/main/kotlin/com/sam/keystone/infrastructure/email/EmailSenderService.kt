package com.sam.keystone.infrastructure.email

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
    private val properties: AppEmailProperties,
) {

    @Async
    fun sendUserVerificationEmail(
        user: User,
        verificationToken: String,
    ): CompletableFuture<Boolean> {

        val subject = "Verify Your Email - Keystone"
        val verifyLink = "${properties.verifyEmailRedirect}?token=${verificationToken}"

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

    @Async
    fun sendUserEmailChangeMail(user: User, newMail: String, token: String): CompletableFuture<Boolean> {
        val subject = "Update Email - Keystone"
        val verifyLink = "${properties.updateEmailRedirect}?token=${token}&confirm=true"

        // Prepare template context
        val template = pebbleEngine.getTemplate("email_change")
        val context = mapOf(
            "user_name" to user.userName,
            "confirm_link" to verifyLink,
            "new_email" to newMail
        )
        val writer = StringWriter()
        template.evaluate(writer, context)
        val htmlContent = writer.toString()

        return emailSender.sendEmail(title = subject, content = htmlContent, recipient = newMail)
    }
}