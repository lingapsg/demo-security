package com.example.demo;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.WebTestClient;

@AutoConfigureWebTestClient
@SpringBootTest
public class DemoIT {

    @Autowired
    private WebTestClient webTestClient;


    @Test
    void testUnrestrictedEndpointWithAuthorizationHeader() {
        webTestClient.get()
                .uri("/api/unrestricted")
                .header(HttpHeaders.AUTHORIZATION, "Bearer token") // fails when passing token
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void testUnrestrictedEndpoint() {
        webTestClient.get()
                .uri("/api/unrestricted")
                .exchange()
                .expectStatus().isOk();
    }

    @SneakyThrows
    @Test
    void testRestrictedEndpoint() {
        webTestClient.get()
                .uri("/api/restricted")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + RSAHelper.getJWSToken())
                .exchange()
                .expectStatus().isOk();
    }
}
