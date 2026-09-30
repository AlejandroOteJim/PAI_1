package org.example.crypto;

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import java.util.Base64;

public class SecurityMiddleware implements Handler<RoutingContext> {

    // Clave secreta compartida (el compañero de la Parte A te la pasará al instanciar este middleware)
    private final byte[] secretKey;

    public SecurityMiddleware(byte[] secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public void handle(RoutingContext ctx) {
        // 1. Extraemos las cabeceras de seguridad requeridas por el enfoque API REST
        String signature = ctx.request().getHeader("X-Signature");
        String nonce = ctx.request().getHeader("X-Nonce");
        String timestampStr = ctx.request().getHeader("X-Timestamp");

        // Si falta alguna cabecera, bloqueamos la petición inmediatamente
        if (signature == null || nonce == null || timestampStr == null) {
            ctx.response().setStatusCode(400).end("Faltan cabeceras de seguridad requeridas.");
            return;
        }

        // 2. Validamos el Timestamp para evitar paquetes caducados
        try {
            long timestamp = Long.parseLong(timestampStr);
            if (!NonceStore.isTimestampValid(timestamp)) {
                ctx.response().setStatusCode(401).end("Ataque detectado: El paquete ha caducado.");
                return;
            }
        } catch (NumberFormatException e) {
            ctx.response().setStatusCode(400).end("Formato de Timestamp inválido.");
            return;
        }

        // 3. Validamos el Nonce contra la base de memoria (Protección Anti-Replay)
        if (!NonceStore.registerAndCheckNonce(nonce)) {
            ctx.response().setStatusCode(401).end("Ataque de Replay detectado: Nonce duplicado.");
            return;
        }

        // 4 y 5. Verificación de Integridad y Autenticidad (HMAC) en tiempo constante
        String body = ctx.body().asString();
        if (body == null || body.isEmpty()) {
            ctx.response().setStatusCode(400).end("El cuerpo de la transacción (JSON) está vacío.");
            return;
        }

        // Llamamos a la nueva función validadora de nuestro HmacSigner
        if (!HMACSigner.verifyHmac(body, signature, secretKey)) {
            ctx.response().setStatusCode(401).end("Firma HMAC inválida: El mensaje ha sido alterado.");
            return;
        }

        // 6. ¡Todo seguro! Pasamos el control al compañero de la Parte A para que procese la transferencia
        ctx.next();
    }
}