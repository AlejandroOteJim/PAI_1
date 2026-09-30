package org.example.crypto;

import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;


//RS3. Protección contra Ataques de Replay (Reintervención)
public class NonceStore {

    // Almacenamos los Nonces en memoria. Usamos ConcurrentHashMap para que sea seguro
    // si llegan múltiples peticiones al servidor exactamente al mismo tiempo.
    private static final Set<String> seenNonces = ConcurrentHashMap.newKeySet();

    // Ventana de tiempo máxima aceptada (ej. 5 minutos = 300 segundos)
    private static final long TIME_WINDOW_SECONDS = 300;

    /**
     * 1. Comprueba si el timestamp de la petición está dentro del margen de tiempo permitido.
     * Esto evita que un atacante guarde un mensaje de hoy y lo reenvíe mañana.
     */
    public static boolean isTimestampValid(long requestTimestamp) {
        long currentTimestamp = Instant.now().getEpochSecond();
        // Calculamos la diferencia absoluta en segundos
        long difference = Math.abs(currentTimestamp - requestTimestamp);

        return difference <= TIME_WINDOW_SECONDS;
    }

    /**
     * 2. Comprueba si el Nonce es único y lo registra.
     * Si el Nonce ya estaba registrado, significa que es un Replay Attack (Mensaje duplicado).
     */
    public static boolean registerAndCheckNonce(String nonce) {
        // El método add() devuelve 'true' si el nonce es nuevo y se guarda con éxito.
        // Devuelve 'false' si el nonce ya existía en la lista (Ataque detectado).
        return seenNonces.add(nonce);
    }
}