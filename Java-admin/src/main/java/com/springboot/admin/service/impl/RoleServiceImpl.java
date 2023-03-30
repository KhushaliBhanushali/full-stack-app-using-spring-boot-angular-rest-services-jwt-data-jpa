package com.springboot.admin.service.impl;

import javax.transaction.Transactional;

import org.springframework.stereotype.Service;

import com.springboot.admin.dao.RoleDao;
import com.springboot.admin.entity.Role;
import com.springboot.admin.service.RoleService;

@Service
@Transactional
public class RoleServiceImpl implements RoleService{
	
	private RoleDao roleDao;

	public RoleServiceImpl(RoleDao roleDao) {
		super();
		this.roleDao = roleDao;
	}

	@Override
	public Role createRole(String roleName) {
		return roleDao.save(new Role(roleName));
	}

}
