package com.sam.keystone.infrastructure.email

import com.sendgrid.Method
import com.sendgrid.Request
import com.sendgrid.SendGrid
import com.sendgrid.helpers.mail.Mail
import com.sendgrid.helpers.mail.objects.Content
import com.sendgrid.helpers.mail.objects.Email
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Async
import org.springframework.stereotype.Component
import java.io.IOException
import java.util.concurrent.CompletableFuture

@Component
class EmailSender(private val properties: EmailProperties) {

    private val logger = LoggerFactory.getLogger(this::class.java)

    @Async
    fun sendEmail(recipient: String, title: String, content: String): CompletableFuture<Boolean> {
        // prepare the email to send
        val fromEmail = Email(properties.senderEmail)
        val toEmail = Email(recipient)
        val contentType = Content("text/html", content)
        val composition = Mail(fromEmail, title, toEmail, contentType)

        // send the mail finally
        return try {
            val sendGrid = SendGrid(properties.apiKey)

            val request = Request().apply {
                method = Method.POST
                endpoint = "mail/send"
                body = composition.build()
            }
            val response = sendGrid.api(request)
            logger.debug("SendGrid Response: ${response.statusCode}")
            CompletableFuture.completedFuture(true)
        } catch (e: IOException) {
            logger.error("Sendgrid response failed :${e.message}", e)
            CompletableFuture.completedFuture(false)
        } catch (e: Exception) {
            CompletableFuture.failedFuture(e)
        }
    }

}