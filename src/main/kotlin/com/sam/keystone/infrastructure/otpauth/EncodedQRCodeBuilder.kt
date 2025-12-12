package com.sam.keystone.infrastructure.otpauth

import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.springframework.stereotype.Component
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO
import kotlin.io.encoding.Base64

@Component
class EncodedQRCodeBuilder {

    fun base64EncodedImage(otpAuthURL: String): String {
        // encode the content into a qr code
        val writer = QRCodeWriter()
        val bitMatrix = writer.encode(otpAuthURL, BarcodeFormat.QR_CODE, 300, 300)

        // copy the content of the qr code into a buffer image
        val width = bitMatrix.width
        val height = bitMatrix.height
        val image = BufferedImage(width, height, BufferedImage.TYPE_INT_RGB)

        for (x in 0 until width) {
            for (y in 0 until height) {
                val gray = if (bitMatrix[x, y]) 0 else 255
                val rgb = (gray shl 16) or (gray shl 8) or gray
                image.setRGB(x, y, rgb)
            }
        }

        // save the buffer image into a base64 encoded message
        val bytes = ByteArrayOutputStream()
        ImageIO.write(image, "png", bytes)
        return Base64.encode(bytes.toByteArray())
    }
}