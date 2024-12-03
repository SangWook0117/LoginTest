package com.example.testt.jwt;

import java.io.IOException;

import org.springframework.web.filter.GenericFilterBean;

import com.example.testt.user.repository.RefreshRepository;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilterBean {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }
    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        //path and method verify
        String requestUri = request.getRequestURI(); //uri에서 path값을 꺼내서 logout요청인지 확인
        if(!requestUri.matches("^\\/logout")) {
            filterChain.doFilter(request, response);
            return; //로그아웃이 아니면 다음필터로 넘어감
        }

        String requestMethod = request.getMethod();
        if(!requestMethod.equals("POST")) {
            filterChain.doFilter(request, response);
            return; //로그아웃이더라도 포스트 요청이 아니면 넘어감
        }

        //쿠키값 얻어오기
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for(Cookie cookie : cookies) {
            if(cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }

        //리프레시 토큰에 값이 있는지 확인
        if(refresh == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //만료시간이 지났는지 확인
        try {
            jwtUtil.isExpired(refresh);
        } catch(ExpiredJwtException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);
        if(!category.equals("refresh")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        // 리프레시 토큰이 DB에 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if(!isExist) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //로그아웃 진행
        //Refresh 토큰을 DB에서 제거
        refreshRepository.deleteByRefresh(refresh);

        //Refresh 토큰 Cookie 값 0
        Cookie cookie = new Cookie("refresh", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);
    }
    
}
