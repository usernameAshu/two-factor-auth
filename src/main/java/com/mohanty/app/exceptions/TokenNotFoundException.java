package com.mohanty.app.exceptions;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class TokenNotFoundException extends UsernameNotFoundException {

	public TokenNotFoundException(String msg) {
		super(msg);
		// TODO Auto-generated constructor stub
	}

	public TokenNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
		// TODO Auto-generated constructor stub
	}

}
