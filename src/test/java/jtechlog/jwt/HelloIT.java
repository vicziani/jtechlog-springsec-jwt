package jtechlog.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HelloIT {

    @Autowired
    WebTestClient webClient;

    @Test
    void hello() {
        webClient
                .get()
                .uri("/api/hello")
                .exchange()
                .expectStatus().isUnauthorized();

    }

    @Test
    void loginAndHello() {
        var token = webClient
                .post()
                .uri("/api/auth")
                .bodyValue(new UserCredentials("user", "user"))
                .exchange()
                .expectStatus().isOk()
                .returnResult(AuthorizationResponse.class)
                .getResponseCookies()
                .get("token")
                .get(0)
                .getValue();

        webClient
                .get()
                .uri("/api/hello")
                .cookie("token", token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(HelloResponse.class).value(response -> assertEquals("Hello JWT!", response.getMessage()));

    }
}
