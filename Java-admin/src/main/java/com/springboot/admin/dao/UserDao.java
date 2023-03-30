package com.springboot.admin.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.springboot.admin.entity.User;

public interface UserDao extends JpaRepository<User, Long>{

	User findByEmail(String email);
}
