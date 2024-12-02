package com.example.testt.jwt;

import java.io.IOException;
import java.io.PrintWriter;

import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.testt.user.dto.CustomUserDetails;
import com.example.testt.user.entity.UserEntity;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {
    
    private final JWTUtil jwtUtil;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 단일 토큰 검증 필터
        // //request에서 Authorization 헤더를 찾음
        // String authorization = request.getHeader("Authorization");

        // //Authorization 헤더 검증
        // if(authorization == null || !authorization.startsWith("Bearer ")) {
        //     System.out.println("token null");
        //     filterChain.doFilter(request, response);
        //     //조건이 해당되면 메서도 종료(필수)
        //     return;
        // }
        // //Bearer 와 토큰값을 분리해서 토큰값만 String token으로 저장
        // String token = authorization.split(" ")[1];

        // //토큰 소멸 시간 검증
        // if(jwtUtil.isExpired(token)) {
        //     System.out.println("token expired");
        //     filterChain.doFilter(request, response);

        //     return;
        // }

        // String username = jwtUtil.getUsername(token);
        // String role = jwtUtil.getRole(token);

        // UserEntity userEntity = new UserEntity();

        // userEntity.setUsername(username);
        // userEntity.setPassword("temppassword");
        // userEntity.setRole(role);

        // CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        // SecurityContextHolder.getContext().setAuthentication(authToken);

        // 다중 토큰 검증 필터
        //헤더에서 토큰을 꺼냄
        String accessToken = request.getHeader("access");

        // 토큰이 없으면 다음 필터로 넘김
        if(accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        } // if
        // 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
        try{
            jwtUtil.isExpired(accessToken);
        } catch(ExpiredJwtException e) {
            //response body
            PrintWriter writer = response.getWriter();
            writer.print("access token expired");
            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        } // try/catch
        // 토큰이 access인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(accessToken);

        if(!category.equals("access")) {
            //response body
            PrintWriter writer = response.getWriter();
            writer.print("invalid access token");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        } // if
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }  
}
