package com.example.demo;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class BearerTokenConverter implements ServerAuthenticationConverter {

    public static final String BEARER = "bearer ";

    /**
     * This method converts well formed bearer authorization header to {@link BearerTokenAuthenticationToken}
     *
     * @param serverWebExchange
     * @throws InvalidBearerTokenException
     * @return
     */
    @Override
    public Mono<Authentication> convert(ServerWebExchange serverWebExchange) {
        return Mono.justOrEmpty(serverWebExchange)
                .filter(exchange -> exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION))
                .switchIfEmpty(Mono.error(new InvalidBearerTokenException("MISSING_TOKEN")))
                .map(exchange -> exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .filter(bearerToken -> StringUtils.isNotBlank(bearerToken) && StringUtils.startsWithIgnoreCase(bearerToken, BEARER))
                .map(bearerToken -> bearerToken.substring(7))
                .filter(StringUtils::isNotBlank)
                .switchIfEmpty(Mono.error(new InvalidBearerTokenException("INVALID_ACCESS_TOKEN")))
                .map(BearerTokenAuthenticationToken::new);
    }
}