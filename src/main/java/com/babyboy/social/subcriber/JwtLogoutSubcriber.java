package com.babyboy.social.subcriber;

import com.babyboy.social.domain.jwt.UserLogoutEvent;
import com.babyboy.social.utils.jwt.RedisBacklistJwtHelper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import tech.jhipster.config.JHipsterProperties;

@Component
public class JwtLogoutSubcriber implements MessageListener {

    Logger logger = LoggerFactory.getLogger(JwtLogoutSubcriber.class);

    //    @Autowired
    //    private RedisBacklistJwtHelper redisBacklistJwtHelper;

    private JHipsterProperties jHipsterProperties;
    private RedisTemplate<String, Object> redisTemplate;

    private final long tokenValidityInMillisecondsForRememberMe;

    public JwtLogoutSubcriber(RedisTemplate<String, Object> redisTemplate, JHipsterProperties jHipsterProperties) {
        this.redisTemplate = redisTemplate;
        this.jHipsterProperties = jHipsterProperties;
        this.tokenValidityInMillisecondsForRememberMe =
            jHipsterProperties.getSecurity().getAuthentication().getJwt().getTokenValidityInSecondsForRememberMe();
    }

    @Override
    public void onMessage(Message message, byte[] bytes) {
        logger.info("Consumed event JwtLogoutSubcriber {}", message);
        try {
            String json = message.toString().substring(message.toString().indexOf("{"));
            UserLogoutEvent userLogoutEvent = new ObjectMapper().readValue(json, UserLogoutEvent.class);
            redisTemplate.opsForHash().put("UserLogoutEvent", userLogoutEvent.getToken(), userLogoutEvent);
            redisTemplate.expire("UserLogoutEvent", this.tokenValidityInMillisecondsForRememberMe, TimeUnit.MILLISECONDS);
            //            redisBacklistJwtHelper.addToken(userLogoutEvent);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            logger.info("Error: {}", e);
        }
    }
}
