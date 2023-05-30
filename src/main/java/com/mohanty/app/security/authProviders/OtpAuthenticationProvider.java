package com.mohanty.app.security.authProviders;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import com.mohanty.app.entity.Otp;
import com.mohanty.app.repository.OtpRepository;
import com.mohanty.app.security.authentications.OtpAuthentication;

@Component
public class OtpAuthenticationProvider implements AuthenticationProvider {
	
	private final OtpRepository otpRepository;
	
	public OtpAuthenticationProvider(OtpRepository otpRepository) {
		this.otpRepository = otpRepository;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		if(!supports(authentication.getClass())) {
			return null;
		}
		
		String username = authentication.getName();
		String otp = String.valueOf(authentication.getCredentials());
		List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
		GrantedAuthority authority = () -> "USER";
		grantedAuthorities.add(authority);
		
		
		Optional<Otp> otpUser = otpRepository.findOtpByUsername(username);
		if(otpUser.isPresent() && otpUser.get().getOtp().equals(otp)) {
			return new OtpAuthentication(username, otp, grantedAuthorities);
		}
		
		throw new BadCredentialsException("Otp is not correct");
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OtpAuthentication.class.equals(authentication);
	}

}
