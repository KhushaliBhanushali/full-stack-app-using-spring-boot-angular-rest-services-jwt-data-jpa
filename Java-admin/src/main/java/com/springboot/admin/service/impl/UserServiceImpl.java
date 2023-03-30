package com.springboot.admin.service.impl;

import javax.transaction.Transactional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.springboot.admin.dao.RoleDao;
import com.springboot.admin.dao.UserDao;
import com.springboot.admin.entity.Role;
import com.springboot.admin.entity.User;
import com.springboot.admin.service.UserService;

@Service
@Transactional
public class UserServiceImpl implements UserService{
	
	private UserDao userDao;
	private RoleDao roleDao;
	private PasswordEncoder passwordEncoder;

	public UserServiceImpl(UserDao userDao, RoleDao roleDao, PasswordEncoder passwordEncoder) {
		super();
		this.userDao = userDao;
		this.roleDao = roleDao;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public User loadUserByEmail(String email) {
		return userDao.findByEmail(email);
	}

	@Override
	public User createUser(String email, String password) {
		String encodedPassword = passwordEncoder.encode(password);
		return userDao.save(new User(email, encodedPassword));
	}

	@Override
	public void assignRoleToUser(String email, String roleName) {
		User user = loadUserByEmail(email);
		Role role = roleDao.findByName(roleName);
		user.assignRoleToUser(role);
	}

}
