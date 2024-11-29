package com.example.testt.user.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.testt.user.dto.UserDTO;
import com.example.testt.user.entity.UserEntity;
import com.example.testt.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    
    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    
    //회원가입
    @Override
    public void joinProcess(UserDTO userDTO) {

        boolean isUser = userRepository.existsByUsername(userDTO.getUsername());
        if(isUser) { //DB에 동일한 username을 가진 사용자가 있으면 메서드 종료
            return;
        }
        //db에 이미 동일한 username을 가진 유저가 존재하는지 검증이 필요함.
        //추가로 정규식 표현도 구현해야함
        UserEntity data = new UserEntity();
        data.setUsername(userDTO.getUsername());
        data.setPassword(bCryptPasswordEncoder.encode(userDTO.getPassword()));
        data.setRole("ROLE_USER");
        System.out.println("회원가입 진행");
        userRepository.save(data);
    }
}
