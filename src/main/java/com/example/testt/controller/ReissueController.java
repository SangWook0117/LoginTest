package com.example.testt.controller;

import java.util.Date;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.testt.jwt.JWTUtil;
import com.example.testt.user.entity.RefreshEntity;
import com.example.testt.user.repository.RefreshRepository;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class ReissueController {
    
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    //하나의 컨트롤러에서 다 처리하지말고 서비스단을 만들어서 처리하는게 좋음

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
        //비어있는 refresh 변수 생성
        String refresh = null;

        Cookie[] cookies = request.getCookies();
        for(Cookie cookie : cookies) {
            if(cookie.getName().equals("refresh")){
                refresh = cookie.getValue(); //쿠키의 이름이 refresh가 있으면 밸류값 적용
            }
        }// for

        //refresh의 값이 없으면 에러코드 출력
        if(refresh == null) {
            //response status code
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        //expired check (리프레시 토큰이 있으면 리프레시 토큰의 유효시간 검사 실시)
        try {
            jwtUtil.isExpired(refresh);
        } catch(ExpiredJwtException e) {
            //response status code
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        //리프레시 토큰이 있으면 카테고리 불러와서 검사 실시
        String category = jwtUtil.getCategory(refresh);

        if(!category.equals("refresh")) {
            //response status code
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }
        //리프레시 토큰이 DB에 저장되어 있는지 확인하는 메서드
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if(!isExist) {
            //response body
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        //모든 검사가 끝나고 문제가 없다면 refresh토큰에서 사용자의 정보를 받아와서 재발급 진행
        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        String newAccess = jwtUtil.createJwt("access", username, role, 600000L);
        //리프레시 토큰을 새로 발급하는 이유는 재사용으로인한 외부공격에 대해서 방어하기 위해서임
        //리프레시 토큰을 새로 발급하면 이전에 사용하던 리프레시 토큰에 대해서는 방어처리를 해야함.
        //서버에 저장 후 서버에 있는 refresh토큰만 사용할 수 있도록 하는 로직을 구현해야 안전함.
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        refreshRepository.deleteByRefresh(refresh); //DB에서 기존에 있던 refresh 토큰 삭제
        addRefreshEntity(username, newRefresh, 86400000L); // DB에 새로운 refresh 토큰 저장

        //새로운 access토큰을 헤더에 추가
        response.setHeader("access", newAccess);
        response.addCookie(createCookie("refresh", newRefresh));

        return new ResponseEntity<>(HttpStatus.OK);
    }
    //쿠키 생성 메서드
    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        //cookie.setSecure(true);
        //cookie.setPath("/");
        cookie.setHttpOnly(true);
        return cookie;
    }
    //리프레시 토큰을 DB에 저장하는 메서드
    private void addRefreshEntity(String username, String refresh, Long expiredMs) {
        //만료일자
        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }

}
