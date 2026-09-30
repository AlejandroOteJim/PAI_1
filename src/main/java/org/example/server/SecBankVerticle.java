package org.example.server;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.mysqlclient.MySQLBuilder;
import io.vertx.mysqlclient.MySQLConnectOptions;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.PoolOptions;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.Tuple;
import org.example.crypto.PasswordHasher;

public class SecBankVerticle extends AbstractVerticle {
    private Pool client;

    @Override
    public void start(Promise<Void> startPromise) {
        setupDatabase();

        setupHttpServer()
                .onSuccess(server -> {
                    System.out.println("Servidor SecBank desplegado en HTTP puerto 8080 (Texto plano).");
                    startPromise.complete();
                })
                .onFailure(err -> {
                    System.err.println("Fallo estructural de inicio: " + err.getMessage());
                    startPromise.fail(err);
                });
    }


    private void setupDatabase() {
        MySQLConnectOptions connectOptions = new MySQLConnectOptions()
                .setPort(3306)
                .setHost("localhost")
                .setDatabase("secbank")
                .setUser("root")
                .setPassword("root");

        PoolOptions poolOptions = new PoolOptions().setMaxSize(5);

        this.client = (Pool) MySQLBuilder.client()
                .with(poolOptions)
                .connectingTo(connectOptions)
                .using(vertx)
                .build();
    }

    private io.vertx.core.Future<io.vertx.core.http.HttpServer> setupHttpServer(){
        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());

        router.post("/api/v1/login").handler(ctx -> {
            try {
                JsonObject payload = ctx.body().asJsonObject();
                String username = payload.getString("username");
                String password = payload.getString("password");

                client.preparedQuery("SELECT * FROM users WHERE username = ?")
                        .execute(Tuple.of(username))
                        .onSuccess(rows -> {
                            if (!rows.iterator().hasNext()) {
                                ctx.response().setStatusCode(404).putHeader("content-type", "application/json")
                                        .end(new JsonObject().put("error", "Usuario no encontrado").encode());
                                return;
                            }

                            Row row = rows.iterator().next();
                            String storedSalt = row.getString("salt");
                            String storedHash = row.getString("password_hash");

                            boolean passwordOk = PasswordHasher.verifyPassword(password, storedSalt, storedHash);

                            if (!passwordOk) {
                                ctx.response().setStatusCode(401).putHeader("content-type", "application/json")
                                        .end(new JsonObject().put("error", "Credenciales incorrectas").encode());
                                return;
                            }

                            ctx.response().setStatusCode(200).putHeader("content-type", "application/json")
                                    .end(new JsonObject().put("status", "Login correcto").encode());
                        })
                        .onFailure(err -> ctx.response().setStatusCode(500)
                                .end(new JsonObject().put("error", err.getMessage()).encode()));

            } catch (Exception e) {
                ctx.response().setStatusCode(400)
                        .end(new JsonObject().put("error", "Error procesando JSON").encode());
            }
        });

        router.post("/api/v1/register").handler(ctx -> {
            try {
                JsonObject payload = ctx.body().asJsonObject();
                String username = payload.getString("username");
                String password = payload.getString("password");

                if (username == null || username.isBlank() || password == null || password.isBlank()) {
                    ctx.response().setStatusCode(400).putHeader("content-type", "application/json")
                            .end(new JsonObject().put("error", "username y password son obligatorios").encode());
                    return;
                }

                String salt = PasswordHasher.generateSalt();
                String passwordHash = PasswordHasher.hashPassword(password, salt);

                client.preparedQuery("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)")
                        .execute(Tuple.of(username, passwordHash, salt))
                        .onSuccess(rows -> {
                            ctx.response().setStatusCode(201).putHeader("content-type", "application/json")
                                    .end(new JsonObject().put("status", "Usuario registrado correctamente").encode());
                        })
                        .onFailure(err -> {
                            if (err.getMessage() != null && err.getMessage().contains("Duplicate entry")) {
                                ctx.response().setStatusCode(409).putHeader("content-type", "application/json")
                                        .end(new JsonObject().put("error", "El usuario ya existe").encode());
                            } else {
                                ctx.response().setStatusCode(500).putHeader("content-type", "application/json")
                                        .end(new JsonObject().put("error", err.getMessage()).encode());
                            }
                        });

            } catch (Exception e) {
                ctx.response().setStatusCode(400).putHeader("content-type", "application/json")
                        .end(new JsonObject().put("error", "Error procesando JSON").encode());
            }
        });

        return vertx.createHttpServer().requestHandler(router).listen(8080);
    }


}
