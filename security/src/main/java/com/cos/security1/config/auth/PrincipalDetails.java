package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

//시큐리티가 /login 주소 요청이 오면 낚아채서 로그인 진행
// 로그인 진행이 완료가 되면 session에 만들어 줌 session을 만들어주는데
// 시큐리티가 자신만의 시큐리티 session 공간을 만들어줌(Security ContextHolder) 여기에다가 세션정보를 저장함
// Security ContextHolder에 들어갈 수 있는 Object는 객체는 정해져 있음
// 그 Object 객체는 Authentication 타입 객체이고 Authentication 객체 안에 User 정보가 있어야됨
// User오브젝트 타입은 UserDetails 타입 객체
// 시큐리티 세션 영역(Security Session)에 들어갈 수 있는 객체는
// Authentication 이고 Authentication객체에 User정보를 저장할때의 객체는 UserDetails객체이다.
@Getter
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user; // 콤포지션
    private Map<String, Object> attributes;


    // 일반 로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }
    // OAuth 로그인인
   public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }


    @Override
    public String getName() {
        return null;
    }


    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // 해당 user의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(
                new GrantedAuthority() {
                    @Override
                    public String getAuthority() {
                        return user.getRole();
                    }
                }
        );
        return collection;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 계정 만료되었니
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정 잠겼니
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    //계정 비밀번호가 오래사용한거 아니니
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정 활성화 여부
    @Override
    public boolean isEnabled() {
        return true;
    }
}


