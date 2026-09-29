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

                // Consulta directa a la base de datos, igual que hacías con los sensores
                client.preparedQuery("SELECT * FROM users WHERE username = ?")
                        .execute(Tuple.of(username))
                        .onSuccess(rows -> {
                            if (!rows.iterator().hasNext()) {
                                ctx.response().setStatusCode(404).putHeader("content-type", "application/json")
                                        .end(new JsonObject().put("error", "Usuario no encontrado").encode());
                                return;
                            }

                            // Extraemos los datos del usuario de la fila devuelta
                            Row row = rows.iterator().next();
                            int failedAttempts = row.getInteger("failed_attempts");

                            // Aquí meteremos la comprobación de si está bloqueado (locked_until)
                            // y la validación del Hash.

                            ctx.response().setStatusCode(200).putHeader("content-type", "application/json")
                                    .end(new JsonObject().put("status", "Usuario encontrado en DB!").encode());
                        })
                        .onFailure(err -> ctx.response().setStatusCode(500)
                                .end(new JsonObject().put("error", err.getMessage()).encode()));

            } catch (Exception e) {
                ctx.response().setStatusCode(400)
                        .end(new JsonObject().put("error", "Error procesando JSON").encode());
            }
        });

        return vertx.createHttpServer().requestHandler(router).listen(8080);
    }


}
