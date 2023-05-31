package com.mohanty.app.exceptions;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class OtpNotFoundException extends UsernameNotFoundException {

	public OtpNotFoundException(String msg) {
		super(msg);
		// TODO Auto-generated constructor stub
	}

	public OtpNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
		// TODO Auto-generated constructor stub
	}

}
