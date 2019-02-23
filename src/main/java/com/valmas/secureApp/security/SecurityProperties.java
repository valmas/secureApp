package com.valmas.secureApp.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource("classpath:security-${spring.profiles.active}.properties")
public class SecurityProperties {

    @Value("${security.jwt.secret}")
    public String JWT_SECRET;
    @Value("${security.password}")
    public String PASSWORD;
    @Value("${server.ssl.key-store-password}")
    public String KEYSTORE_PASSWORD;
    @Value("${security.trust-store}")
    public String TRUSTSTORE_PATH;
}
