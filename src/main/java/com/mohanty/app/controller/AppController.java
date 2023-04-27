package com.mohanty.app.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.mohanty.app.entity.Users;
import com.mohanty.app.security.securedUsers.SecurityUser;
import com.mohanty.app.service.SecurityAppService;

@RestController
public class AppController {
	
	private final SecurityAppService service;
	private final PasswordEncoder passwordEncoder;
	
	public AppController(SecurityAppService service, PasswordEncoder passwordEncoder) {
		this.service = service;
		this.passwordEncoder = passwordEncoder;
	}

	@GetMapping("/")
	public String hello(Authentication authentication) {
//		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return "Hello "+ authentication.getName()+" !";
	}
	
	@PostMapping("/user")
	public void createUser(@RequestBody Users user) {
		service.createUser(new SecurityUser(user, passwordEncoder));
	}

}
