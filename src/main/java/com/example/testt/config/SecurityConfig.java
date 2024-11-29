package com.example.testt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.testt.jwt.JWTUtil;
import com.example.testt.jwt.LoginFilter;

import lombok.RequiredArgsConstructor;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {
//     //확인해야 할 파일 SecurityConfig.java, MainController.java, Details, Entity
//     @Bean
//     public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        
//         //경로에 대한 접근권한 설정
//         http
//             .authorizeHttpRequests(auth -> auth
//                 .requestMatchers("/", "/user/loginForm", "/loginProc", "/user/joinForm", "/user/joinProc").permitAll()
//                 .requestMatchers("/admin").hasRole("ADMIN")
//                 .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
//                 .anyRequest().authenticated());
//         //커스텀 로그인페이지 설정
//         http
//             .formLogin(auth -> auth.loginPage("/user/loginForm")
//                 .loginProcessingUrl("/loginProc")
//                 .permitAll());

//         /*
//         http
//             .httpBasic(Customizer.withDefaults());
//         폼로그인 방식 대신 http basic방식으로 사용자의 정보(아이디와 비밀번호)를 Base64 방식으로 인코딩한 뒤 헤더에 담아서 서버에 요청함.
//          */

//         //csrf 사이트 위조방지 설정 (csrf토큰도 보내줘야하는데 보내주지않으면 로그인 되지 않기때문에 disable 시켜줌)
//         //csrf는 요청을 위조하여 사용자가 원하지 않아도 서버측으로 특정 요청을 강제로 보내는 방식이다. (회원 정보 변경, 게시글 CRUD를 사용자 모르게 요청)
//         //http.csrf(auth -> auth.disable());
//         //csrf를 disable 시켜두지 않으면 자동으로 enable되어서 개발환경에서 로그인이 진행되지않는다.
//         //페이지에서 csrf값을 받아줘야 한다. post 요청시 <input type="hidden" name="_csrf" value="{{_csrf.token}}" /> 형식으로 받는다
//         //ajax요청시 html <head> 구획에 <meta name="_csrf" content="{{_csrf.token}}"/>, <meta name="_csrf_header" content={{_csrf.headerName}}/>을 추가해줘야한다
//         //API 서버의 경우 csrf.disable()를 해도된다 JWT를 사용해도 세션을 StateLess방식으로 관리하기 때문에 스프링 시큐리티 csrf enable 설정을 진행하지 않아도 된다.
        
//         //로그아웃 설정
//         http
//             .logout(auth -> auth
//                 .logoutUrl("/logout") //로그아웃 요청 주소, csrf가 enable이면 무조건 post방식으로 요청해주어야함.
//                 .logoutSuccessUrl("/"));
//         //오류가 나올 시 application.properties에 spring.mustache.servlet.expose-request-attributes=true 설정을 해줘야함(라이브러리가 mustache기준)

//         //다중로그인 설정
//         http
//             .sessionManagement(auth -> auth // 메소드를 통한 설정을 진행하려고한다.
//                 .maximumSessions(1) //하나의 아이디에 대한 다중 로그인 허용 개수
//                 .maxSessionsPreventsLogin(true)); // 다중 로그인 개수를 초과하였을 경우 처리방법, true: 초과시 새로운 로그인 차단, false: 초과시 기존 세션 하나 삭제
//         //세션 고정 보호
//         http
//             .sessionManagement(auth -> auth
//                 .sessionFixation().none()); // none: 로그인시 세션 정보 변경안함. newSession: 로그인 시 새로 생성 changeSessionId: 로그인 시 동일한 세션에 대한 id 변경
//         //none으로할 시 위험, changeSessionId를 주로 사용해서 해커의 공격으로부터 보호함.
//         return http.build();
//     }

//     // 비밀번호 해시화 매서드 (DB에 저장할때 비밀번호를 해쉬화 해서 저장한다.)
//     @Bean
//     public BCryptPasswordEncoder bCryptPasswordEncoder() {

//         return new BCryptPasswordEncoder();
//     }

//     //RoleHierarchy 계층권한 설정
//     /*
//     @Bean
//     public RoleHierarchy roleHierarchy() {
//         return RoleHierarchyImpl.fromHierarchy("""
//             ROLE_C > ROLE_B
//             ROLE_B > ROLE_A
//         """); 또는
//         return RoleHierarchyImpl.withDefaultRolePrefix()
//             .role("C").implies("B")
//             .role("B").implies("A")
//             .build();
//         두개중 아무거나 사용해도 상관없음.
//     }
//      */
// }

//JWT토큰 방식을 사용했을때 Security 설정방식
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //csrf비활성화
        http.csrf(auth -> auth.disable());
        //Form 로그인 방식 비활성화
        http.formLogin(auth -> auth.disable());
        //http basic 인증 방식 비활성화]
        http.httpBasic(auth -> auth.disable());

        //경로에 대한 권한 설정
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/user/loginForm", "/", "/user/joinForm", "/login").permitAll()
            .requestMatchers("/admin").hasRole("ADMIN")
            .anyRequest().authenticated());
        //커스텀 필터 설정 (폼로그인 대신 설정)
        http
            .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);
            //내가 만든 LoginFilter.java를 생성해서 등록, addFilterAt은 사용할 필터의 위치를 지정, UsernamePasswordAuthenticationFilter 필터를 대체하는 필터를 설정해주는것 
        //세션 설정 (JWT토큰 방식에서는 세션을 StateLess 방식으로 관리하기 때문에 세션 설정을 해주어야함)
        http
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
    //회원정보를 저장할때는 비밀번호를 해시화해서 관리하기 때문에 넣어주는 메서드
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
    //AuthenticationManager를 반환해주는 메서드를 설정
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}