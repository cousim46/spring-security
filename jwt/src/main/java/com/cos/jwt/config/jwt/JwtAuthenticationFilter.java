package com.cos.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 이 필터가 존재
// 이 필터가 동작하는 시기는 /login을 요청을 해서 username과 password를 post로 전송하면
// UsernamePasswordAuthenticationFilter 이 필터가 동작함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("---------------attemptAuthentication 실행됨----------------");
        /**
         1. userId와 password를 받아서
         2. 정상인지 로그인 시도를 해본다 authenticationManager로 로그인 시도를 하면
         PrincipalDetailsService가 호출됨 호출되면 loadUserByUsername이 자동으로 실행됨

         3. PrincipalDetails를 세션에 담는다 세션에 담는이유는 권한 관리를 위해서

         4. JWT토큰을 만들어서 응답해주면 됨
         */
        return super.attemptAuthentication(request, response);
    }
}
