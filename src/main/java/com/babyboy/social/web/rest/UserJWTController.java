package com.babyboy.social.web.rest;

import com.babyboy.social.domain.jwt.UserLogoutEvent;
import com.babyboy.social.publisher.RedisMessagePublisher;
import com.babyboy.social.security.SecurityUtils;
import com.babyboy.social.security.jwt.JWTFilter;
import com.babyboy.social.security.jwt.TokenProvider;
import com.babyboy.social.web.rest.vm.LoginVM;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.concurrent.TimeUnit;
import javax.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Controller to authenticate users.
 */
@RestController
@RequestMapping("/api")
public class UserJWTController {

    Logger logger = LoggerFactory.getLogger(UserJWTController.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final TokenProvider tokenProvider;

    private final ReactiveAuthenticationManager authenticationManager;

    @Autowired
    private RedisMessagePublisher redisMessagePublisher;

    //    @Autowired
    //    private RedisTemplate redisTemplate;

    public UserJWTController(TokenProvider tokenProvider, ReactiveAuthenticationManager authenticationManager) {
        this.tokenProvider = tokenProvider;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/authenticate")
    public Mono<ResponseEntity<JWTToken>> authorize(@Valid @RequestBody Mono<LoginVM> loginVM) {
        return loginVM
            .flatMap(login ->
                authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()))
                    .flatMap(auth -> Mono.fromCallable(() -> tokenProvider.createToken(auth, login.isRememberMe())))
            )
            .map(jwt -> {
                HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.add(JWTFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);
                return new ResponseEntity<>(new JWTToken(jwt), httpHeaders, HttpStatus.OK);
            });
    }

    @GetMapping("/logout")
    public ResponseEntity<?> logout(ServerHttpRequest request) {
        //        String username = SecurityUtils.getCurrentUserLogin().block();
        String bearerToken = request.getHeaders().getFirst(AUTHORIZATION_HEADER);
        UserLogoutEvent logoutEvent = new UserLogoutEvent("", bearerToken.substring(7));
        try {
            //            redisTemplate.opsForHash().put("UserLogoutEvent", logoutEvent.getToken(), logoutEvent);
            //            redisTemplate.expire("UserLogoutEvent", 10, TimeUnit.SECONDS);
            redisMessagePublisher.publish(new ObjectMapper().writeValueAsString(logoutEvent));
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            logger.info("Error!");
            return ResponseEntity.badRequest().body("Error!");
        }
        logger.info("User has successfully logged out from the system!");
        return ResponseEntity.ok("User has successfully logged out from the system!");
    }

    /**
     * Object to return as body in JWT Authentication.
     */
    static class JWTToken {

        private String idToken;

        JWTToken(String idToken) {
            this.idToken = idToken;
        }

        @JsonProperty("id_token")
        String getIdToken() {
            return idToken;
        }

        void setIdToken(String idToken) {
            this.idToken = idToken;
        }
    }
}
