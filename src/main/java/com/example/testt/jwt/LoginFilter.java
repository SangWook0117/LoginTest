package com.example.testt.jwt;

import java.util.Collection;
import java.util.Iterator;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.testt.user.dto.CustomUserDetails;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

//이 클래스는 UsernamePasswordAuthenticationFilter를 커스텀해서 사용할 클래스
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    
    //이 친구가 DTO값을 받아서 검증
    private final AuthenticationManager authenticationManager;

    private final JWTUtil jwtUtil;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //클라이언트 요청에서 username, password를 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        //username, password 값을 DTO처럼 담아서 UsernamePasswordAuthenticationToken(DTO)를 AuthenticationManager에 전달해서 검증한다.
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null); //3번째는 role값같은거

        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
          CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

          // 사용자 이름 확인
          String username = customUserDetails.getUsername();

          Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
          Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
          GrantedAuthority auth = iterator.next();

          // 롤값 확인
          String role = auth.getAuthority();

          String token = jwtUtil.createJwt(username, role, 60*60*10L); //JWT가 살아있을시간

          response.addHeader("Authorization", "Bearer " + token);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        response.setStatus(401);
    }
}
