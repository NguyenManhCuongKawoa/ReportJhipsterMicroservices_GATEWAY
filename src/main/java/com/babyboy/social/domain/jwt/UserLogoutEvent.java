package com.babyboy.social.domain.jwt;

import java.io.Serializable;
import java.time.Instant;
import java.util.Date;
import org.springframework.data.redis.core.RedisHash;

@RedisHash(value = "UserLogoutEvent")
public class UserLogoutEvent implements Serializable {

    private String userEmail;
    private String token;
    private Date eventTime;

    public UserLogoutEvent() {}

    public UserLogoutEvent(String userEmail, String token) {
        this.userEmail = userEmail;
        this.token = token;
        this.eventTime = Date.from(Instant.now());
    }

    public String getUserEmail() {
        return userEmail;
    }

    public String getToken() {
        return token;
    }

    public Date getEventTime() {
        return eventTime;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public void setEventTime(Date eventTime) {
        this.eventTime = eventTime;
    }
}
