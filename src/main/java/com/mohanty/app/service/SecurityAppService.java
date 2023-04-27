package com.mohanty.app.service;

import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Service;

import com.mohanty.app.security.securedUsers.SecurityUser;

@Service
public class SecurityAppService {
	
	private final JdbcUserDetailsManager userDetailsManager;

	public SecurityAppService(JdbcUserDetailsManager userDetailsManager) {
		this.userDetailsManager = userDetailsManager;
	};
	
	
	public void createUser(SecurityUser user) {
		userDetailsManager.createUser(user);
	}
	

}
