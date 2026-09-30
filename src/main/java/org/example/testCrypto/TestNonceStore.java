package org.example.testCrypto;

import org.example.crypto.NonceStore;
import org.testng.annotations.Test;
import java.time.Instant;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class TestNonceStore {

    @Test
    public void pruebaDeteccionAtaqueReplay() {
        String noncePrueba = "nonce-unico-test-12345";

        // Primer intento legítimo
        boolean primerIntento = NonceStore.registerAndCheckNonce(noncePrueba);
        assertTrue(primerIntento, "El primer uso del Nonce debe ser aceptado por el servidor.");

        // Segundo intento fraudulento (Replay Attack)
        boolean segundoIntento = NonceStore.registerAndCheckNonce(noncePrueba);
        assertFalse(segundoIntento, "El segundo uso del Nonce debe ser rechazado como ataque Replay.");
    }

    @Test
    public void pruebaTimestampValido() {
        // Creamos un timestamp de hace 30 segundos (dentro del límite permitido de 300 segundos)
        long timestampReciente = Instant.now().getEpochSecond() - 30;

        boolean esValido = NonceStore.isTimestampValid(timestampReciente);
        assertTrue(esValido, "El timestamp reciente debe considerarse válido.");
    }

    @Test
    public void pruebaTimestampCaducado() {
        // Creamos un timestamp de hace 1 hora (fuera del límite)
        long timestampAntiguo = Instant.now().getEpochSecond() - 3600;

        boolean esValido = NonceStore.isTimestampValid(timestampAntiguo);
        assertFalse(esValido, "El timestamp antiguo debe ser rechazado.");
    }
}