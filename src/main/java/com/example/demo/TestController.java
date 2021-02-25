package com.example.demo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@Slf4j
@RequestMapping("api/")
@RestController
public class TestController {

    @GetMapping("unrestricted")
    public Mono<String> unrestricted() {
        return Mono.just("unrestricted");
    }

    @GetMapping("restricted")
    public Mono<String> restricted() {
        return Mono.just("restricted");
    }
}
