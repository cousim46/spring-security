package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

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

        // 1. userId와 password를 받아서
        try {
//            BufferedReader reader = request.getReader();
//            String input = null;
//            if((input =reader.readLine()) != null) {
//                System.out.println(input);

            ObjectMapper objectMapper = new ObjectMapper(); // json 데이터를 파싱함
            User user = objectMapper.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            // Authentication이 실행되면 PrincipalDetailsService의 loadUserByUsername() 함수가 실행되는데
            // 실행된 후 정상이면 authentication이 리턴됨
            // DB에 있는 username과 password가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 로그인이 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨 = " + principalDetails.getUser().getUsername()); // 값이 있다는건 로그인이 정상적으로 되었다는 뜻
            return authentication; //authentication 객체가 세션에 저장됨 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음, 근데 단지 권한 처리때문에 SESSION 영역에 넣어줘야됩니다.

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
    // 2. 정상인지 로그인 시도를 해본다 authenticationManager로 로그인 시도를 하면
    // PrincipalDetailsService가 호출됨 호출되면 loadUserByUsername이 자동으로 실행됨

    // 3. PrincipalDetails를 세션에 담는다 세션에 담는이유는 권한 관리를 위해서

    //4. JWT토큰을 만들어서 응답해주면 됨

    // attemptAuthentication실행후 인증이 정상적으로 되었으면  successfulAuthentication 함수가 실행됨
    // 여기서 jwt 토큰을 만들어서 request요청한 사용자에게 JWT 토큰을 response해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));
        System.out.println("jwtToken = " + jwtToken);
        System.out.println("successfulAuthentication실행됨 : 인증이 완료되었다는뜻");
        response.addHeader("Authorization","Bearer " + jwtToken);
    }
}
