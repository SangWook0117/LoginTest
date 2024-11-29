package com.example.testt.user.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.example.testt.user.dto.UserDTO;
import com.example.testt.user.service.UserService;

import lombok.RequiredArgsConstructor;

@Controller
@RequestMapping("user")
@RequiredArgsConstructor
public class UserController {
    
    private final UserService userService;

    @GetMapping("/loginForm")
    public String loginForm() {
        return "user/loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        System.out.println("회원가입창");
        return "user/joinForm";
    }

    @PostMapping("/joinProc")
    public String joinProcess(UserDTO userDTO) {
        System.out.println(userDTO.getUsername());
        userService.joinProcess(userDTO);
        return "redirect:/loginForm";
    }
}
