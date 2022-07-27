package com.babyboy.social.utils.jwt;

import com.babyboy.social.domain.jwt.UserLogoutEvent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class RedisBacklistJwtHelper {

    @Autowired
    private RedisTemplate redisTemplate;

    public void addToken(UserLogoutEvent userLogoutEvent) {
        redisTemplate.opsForHash().put("UserLogoutEvent", userLogoutEvent.getToken(), userLogoutEvent);
    }

    public boolean checkTokenInBackListCache(String token) {
        return redisTemplate.opsForHash().hasKey("UserLogoutEvent", token);
    }
}
