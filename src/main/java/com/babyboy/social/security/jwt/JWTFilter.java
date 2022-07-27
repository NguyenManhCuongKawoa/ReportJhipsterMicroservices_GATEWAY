package com.babyboy.social.security.jwt;

import com.babyboy.social.utils.jwt.RedisBacklistJwtHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Filters incoming requests and installs a Spring Security principal if a header corresponding to a valid user is
 * found.
 */
@Component
public class JWTFilter implements WebFilter {

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final TokenProvider tokenProvider;

    private final RedisTemplate redisTemplate;

    //    @Autowired
    //    private RedisBacklistJwtHelper redisBacklistJwtHelper;

    public JWTFilter(TokenProvider tokenProvider, RedisTemplate redisTemplate) {
        this.tokenProvider = tokenProvider;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String jwt = resolveToken(exchange.getRequest());
        //        if (StringUtils.hasText(jwt) && this.tokenProvider.validateToken(jwt) && !redisBacklistJwtHelper.checkTokenInBackListCache(jwt)) {
        if (
            StringUtils.hasText(jwt) && this.tokenProvider.validateToken(jwt) && !redisTemplate.opsForHash().hasKey("UserLogoutEvent", jwt)
        ) {
            Authentication authentication = this.tokenProvider.getAuthentication(jwt);
            return chain.filter(exchange).subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));
        }
        return chain.filter(exchange);
    }

    public String resolveToken(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
