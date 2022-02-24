package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CorsFilter corsFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용 안하겠다 무상태로 만들겠다
                .and()
                .addFilter(corsFilter) // @CrossOrigin는 인증이 없을때 인증이 있을대는 filter에 등록
                .formLogin().disable() // form 로그인 사용 x
                .httpBasic().disable()
                .authorizeRequests()
                .antMatchers("api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();


    }
}
