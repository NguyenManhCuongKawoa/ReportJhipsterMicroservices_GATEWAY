package com.babyboy.social.config.myconfig;

import com.babyboy.social.publisher.MessagePublisher;
import com.babyboy.social.publisher.RedisMessagePublisher;
import com.babyboy.social.subcriber.JwtLogoutSubcriber;
import java.time.Duration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import tech.jhipster.config.JHipsterProperties;

@Configuration
@EnableRedisRepositories
public class RedisConfig {

    public static final String JWT_REDIS_TOPIC = "social-logout-channel";

    private final JHipsterProperties jHipsterProperties;

    public RedisConfig(JHipsterProperties jHipsterProperties) {
        this.jHipsterProperties = jHipsterProperties;
    }

    @Bean
    public RedisTemplate<String, Object> template(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new JdkSerializationRedisSerializer());
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        template.setEnableTransactionSupport(true);
        template.afterPropertiesSet();
        return template;
    }

    @Bean
    public ChannelTopic topic() {
        return new ChannelTopic(JWT_REDIS_TOPIC);
    }

    @Bean
    public MessageListenerAdapter messageListenerAdapter(RedisTemplate redisTemplate) {
        return new MessageListenerAdapter(new JwtLogoutSubcriber(redisTemplate, jHipsterProperties));
    }

    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(
        RedisConnectionFactory connectionFactory,
        RedisTemplate redisTemplate
    ) {
        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);
        container.addMessageListener(messageListenerAdapter(redisTemplate), topic());
        return container;
    }

    @Bean
    public MessagePublisher redisPublisher() {
        return new RedisMessagePublisher();
    }
}
