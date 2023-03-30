package com.springboot.admin.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.springboot.admin.entity.Role;

public interface RoleDao extends JpaRepository<Role, Long>{

	Role findByName(String name);
}
