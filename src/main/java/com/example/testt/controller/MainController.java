package com.example.testt.controller;

import java.util.Collection;
import java.util.Iterator;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class MainController {
    
    @GetMapping("/")
    public String index(Model model) {
        //SecurityContextHolder에서 사용자 정보 가져오기
        String id = SecurityContextHolder.getContext().getAuthentication().getName();
        //Authentication: 현재 인증된 사용자의 인증 정보를 포함하고 있는 객체야. 이 객체를 통해 사용자의 권한 정보 등을 알 수 있어.
        //authorities: 현재 사용자가 가진 권한 목록을 가져와. 이 권한들은 GrantedAuthority 객체의 컬렉션으로 제공돼.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        Iterator<? extends GrantedAuthority> iter = authorities.iterator();
        GrantedAuthority auth = iter.next();
        //role: 위에서 얻은 권한에서 권한의 이름(롤)을 문자열로 가져와서 role 변수에 저장해.
        String role = auth.getAuthority();


        model.addAttribute("id", id);
        model.addAttribute("role", role);

        return "index";
    }
    //로그아웃 컨트롤러
    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);   
        }
        return "redirect:/";
    }
}
