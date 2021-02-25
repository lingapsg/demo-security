package com.example.demo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import reactor.core.publisher.Mono;

import java.util.Collections;

@Slf4j
@EnableReactiveMethodSecurity
@EnableWebFluxSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity serverHttpSecurity) {
        return serverHttpSecurity
                .requestCache()
                .requestCache(NoOpServerRequestCache.getInstance()) // disable cache
                .and()
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .exceptionHandling()
                .authenticationEntryPoint((swe, e) -> Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED)))
                .accessDeniedHandler((swe, e) -> Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN)))
                .and().csrf().disable()
                .authorizeExchange()
                .pathMatchers("/api/unrestricted").permitAll()
                .and()
                .authorizeExchange().anyExchange().authenticated()
                .and()
                .oauth2ResourceServer()
                .jwt(jwtSpec -> jwtSpec.authenticationManager(authenticationManager()))
                .authenticationEntryPoint((swe, e) -> Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED)))
                .accessDeniedHandler((swe, e) -> Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN)))
                .and().build();

    }

    private ReactiveAuthenticationManager authenticationManager() {
        return authentication -> {
            log.info("executing authentication manager");
            return Mono.justOrEmpty(authentication)
                    .filter(auth -> auth instanceof BearerTokenAuthenticationToken)
                    .cast(BearerTokenAuthenticationToken.class)
                    .filter(token -> RSAHelper.verifySigning(token.getToken()))
                    .switchIfEmpty(Mono.error(new BadCredentialsException("Invalid token")))
                    .map(token -> (Authentication) new UsernamePasswordAuthenticationToken(
                            token.getToken(),
                            token.getToken(),
                            Collections.emptyList()
                    ));
        };
    }
}
