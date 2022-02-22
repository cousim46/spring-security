package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
        /** 구글 로그인이 완료된 뒤의 후처리 필요
         1. 코드 받기
         2, 엑세스 토큰 받기(사용자 권한)
         3. 사용자 프로필 정보를 가져옴
         4-1.  가져온 정보를 토대로 회원가입을 자동으로 진행시키기도 함
         4-2. 가져온 정보가 부족할 경우 부족한 정보를 채울 창 띄어줘야됨
         */

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록됨
@EnableGlobalMethodSecurity(securedEnabled = true, // secured 어노텡이션 황성화
        prePostEnabled = true)  // preAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;


    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // /login 라는 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm") // 구글 로그인이 완료된 뒤의 후처리 필요 Tip : 구글 로그인이 되면 코드x  액세스토큰 사용자 프로필 정보를 받느다
                .userInfoEndpoint()
                .userService(principalOauth2UserService);

    }
}
