package com.valmas.secureApp.security;

import com.auth0.jwt.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vavr.control.Option;
import io.vavr.control.Try;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static com.valmas.secureApp.security.SecurityConstants.*;

@RequiredArgsConstructor
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @NonNull
    private AuthenticationManager authenticationManager;
    @NonNull
    private SecurityProperties sp;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {

        return Try.of(req::getInputStream)
                .mapTry(it -> new ObjectMapper().readValue(it, AuthenticationRequest.class))
                .flatMap(it -> CipherUtils.decryptPassword(sp.KEYSTORE_PASSWORD, it.getAlias(), it.getSignature(), sp.TRUSTSTORE_PATH)
                        .map(pass -> authenticationManager.authenticate(
                                new UsernamePasswordAuthenticationToken(it.getAlias(), pass, new ArrayList<>()))))
                .get();
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {

        Option.of(JWT.create()
                .withSubject(((User) auth.getPrincipal()).getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(HMAC512(sp.JWT_SECRET.getBytes()))
        ).forEach(it -> res.addHeader(HEADER_STRING, TOKEN_PREFIX + it));
    }
}