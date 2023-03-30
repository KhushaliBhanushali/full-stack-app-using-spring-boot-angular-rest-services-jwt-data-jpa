package com.springboot.admin.security;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.springboot.admin.entity.User;
import com.springboot.admin.service.UserService;

@Service 
public class UserDetailsServiceImpl implements UserDetailsService{

	private UserService userService;
	
	public UserDetailsServiceImpl(UserService userService) {
		super();
		this.userService = userService;
	}

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		User user = userService.loadUserByEmail(email);
		if(user == null) throw new UsernameNotFoundException("User not found");
		Collection<GrantedAuthority> authorities = new ArrayList<>();
		user.getRoles().forEach(role -> {
			SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role.getName());
			authorities.add(authority);
		});
		org.springframework.security.core.userdetails.User userDetails = new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), authorities);
		return userDetails;
	}

}
