package com.springboot.admin.service;

import com.springboot.admin.entity.User;

public interface UserService {

	User loadUserByEmail(String email);
	
	User createUser(String email, String password);
	
	void assignRoleToUser(String email, String roleName);
	
}
