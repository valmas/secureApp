package com.valmas.secureApp.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.vavr.control.Option;
import io.vavr.control.Try;
import lombok.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.Null;
import java.io.IOException;
import java.util.ArrayList;

import static com.valmas.secureApp.security.SecurityConstants.*;


public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    @NonNull
    private SecurityProperties sp;

    JWTAuthorizationFilter(@NonNull final AuthenticationManager authManager,
                           @NonNull final SecurityProperties sp) {
        super(authManager);
        this.sp = sp;
    }

    @Override
    protected void doFilterInternal(final @NonNull HttpServletRequest req,
                                    final @NonNull HttpServletResponse res,
                                    final @NonNull FilterChain chain) throws IOException, ServletException {

        final UsernamePasswordAuthenticationToken token = Option.of(req.getHeader(HEADER_STRING))
                .filter(it -> it.startsWith(TOKEN_PREFIX))
                .flatMap(it -> getAuthentication(req)).getOrNull();

        SecurityContextHolder.getContext().setAuthentication(token);
        chain.doFilter(req, res);
    }

    @NonNull
    private Option<UsernamePasswordAuthenticationToken> getAuthentication(final @NonNull HttpServletRequest req) {

        return Option.of(req.getHeader(HEADER_STRING))
                .flatMap(it -> Try.of(() -> JWT.require(Algorithm.HMAC512(sp.JWT_SECRET.getBytes()))
                        .build()
                        .verify(it.replace(TOKEN_PREFIX, ""))
                        .getSubject()).toOption()
                ).map(user -> new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>()));
    }

}