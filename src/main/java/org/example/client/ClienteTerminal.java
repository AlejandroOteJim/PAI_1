package org.example.client;
import java.util.Scanner;

public class ClienteTerminal {
    // Instanciamos tu cliente de red que ya tienes en el proyecto
    private static final SecBankClient apiClient = new SecBankClient();

    // Estado de la sesión del usuario
    private static boolean isAuthenticated = false;
    private static String currentUser = null;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean exit = false;

        System.out.println("=========================================");
        System.out.println("            SECBANK - TERMINAL    ");
        System.out.println("=========================================");

        while (!exit) {
            if (!isAuthenticated) {
                mostrarMenuAnonimo();
                int opcion = leerOpcionEntera(scanner);

                switch (opcion) {
                    case 1:
                        manejarRegistro(scanner);
                        break;
                    case 2:
                        manejarLogin(scanner);
                        break;
                    case 3:
                        exit = true;
                        System.out.println("Saliendo de la terminal de SecBank...");
                        break;
                    default:
                        System.out.println("Opción inválida. Inténtalo de nuevo.");
                }
            } else {
                mostrarMenuAutenticado();
                int opcion = leerOpcionEntera(scanner);

                switch (opcion) {
                    case 1:
                        manejarLogout();
                        break;
                    default:
                        System.out.println("Opción inválida. Inténtalo de nuevo.");
                }
            }
        }
        scanner.close();
    }

    private static void mostrarMenuAnonimo() {
        System.out.println("\n--- MENÚ PRINCIPAL ---");
        System.out.println("1. Registrar nuevo usuario");
        System.out.println("2. Iniciar Sesión (Login)");
        System.out.println("3. Salir");
        System.out.print("Elige una opción: ");
    }

    private static void mostrarMenuAutenticado() {
        System.out.println("\n--- BÓVEDA DE SECBANK | Usuario: " + currentUser + " ---");
        System.out.println("1. Cerrar Sesión (Logout)");
        System.out.print("Elige una opción: ");
    }

    private static int leerOpcionEntera(Scanner scanner) {
        try {
            return Integer.parseInt(scanner.nextLine().trim());
        } catch (NumberFormatException e) {
            return -1; // Retorna -1 para que salte el default del switch
        }
    }

    private static void manejarRegistro(Scanner scanner) {
        System.out.println("\n--- REGISTRO DE USUARIO ---");
        System.out.print("Introduce un username: ");
        String user = scanner.nextLine().trim();
        System.out.print("Introduce una password: ");
        String pass = scanner.nextLine().trim();

        System.out.println("Enviando petición al servidor...");

        try {
            // AQUÍ LLAMAMOS DE VERDAD A TU CLIENTE HTTP
            SecBankClient.Response res = apiClient.register(user, pass);

            if (res.status() == 201) {
                System.out.println("Usuario '" + user + "' registrado de verdad en la base de datos.");
            } else {
                System.out.println("El servidor rechazó el registro: " + res.body());
            }
        } catch (Exception e) {
            System.out.println("Error de conexión: " + e.getMessage());
        }
    }

    private static void manejarLogin(Scanner scanner) {
        System.out.println("\n--- INICIO DE SESIÓN ---");
        System.out.print("Username: ");
        String user = scanner.nextLine().trim();
        System.out.print("Password: ");
        String pass = scanner.nextLine().trim();

        System.out.println("Verificando credenciales en la base de datos...");

        try {
            // AQUÍ SE HACE EL POST AL SERVIDOR
            SecBankClient.Response res = apiClient.login(user, pass);

            if (res.status() == 200) {
                isAuthenticated = true;
                currentUser = user;
                System.out.println("Login exitoso. Sesión iniciada y salt recuperado.");
            } else {
                System.out.println("Login fallido (Status " + res.status() + "): " + res.body());
            }
        } catch (Exception e) {
            System.out.println("Error de conexión con el servidor: " + e.getMessage());
        }
    }

    private static void manejarLogout() {
        System.out.println("Cerrando sesión en el servidor...");

        try {
            // Llamada real al servidor con el token Bearer
            SecBankClient.Response res = apiClient.logout();

            if (res.status() == 200) {
                System.out.println("Sesión cerrada correctamente de forma remota.");
            } else {
                System.out.println("El servidor devolvió un error (Status " + res.status() + "): " + res.body());
            }
        } catch (Exception e) {
            System.out.println("Error de conexión al hacer logout: " + e.getMessage());
        } finally {
            // Pase lo que pase con la red, borramos la sesión en la terminal local
            isAuthenticated = false;
            currentUser = null;
            System.out.println("Sesión local terminada.");
        }
    }
}
