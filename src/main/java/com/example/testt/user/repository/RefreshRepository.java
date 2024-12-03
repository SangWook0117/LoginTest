package com.example.testt.user.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.example.testt.user.entity.RefreshEntity;

@Repository
public interface RefreshRepository extends JpaRepository<RefreshEntity, Long>{
    
    public Boolean existsByRefresh(String refresh); // DB에 리프레시 토큰이 있는지 조회하는 메서드

    @Transactional
    public void deleteByRefresh(String refresh); // DB에서 리프레시 토큰을 지우기 위한 메서드
}
