package com.mohanty.app.security.authProviders;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.mohanty.app.entity.Otp;
import com.mohanty.app.repository.OtpRepository;
import com.mohanty.app.security.authentications.OtpAuthentication;

import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class OtpAuthenticationProvider implements AuthenticationProvider {
	
	private final OtpRepository otpRepository;
	private final PasswordEncoder passwordEncoder;
	
	//parameterized constructors from lombok

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		if(!supports(authentication.getClass())) {
			return null;
		}
		
		String username = authentication.getName();
		String otpSecret = String.valueOf(authentication.getCredentials());
		List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
		GrantedAuthority authority = () -> "USER";
		grantedAuthorities.add(authority);
		
		Optional<Otp> dbOtpDetails = otpRepository.findByUsername(username);
		if(dbOtpDetails.isPresent() && passwordEncoder.matches(otpSecret, dbOtpDetails.get().getOtp())) {
			return new OtpAuthentication(username, dbOtpDetails.get().getOtp(),grantedAuthorities);
		}
		
		
		throw new BadCredentialsException("Otp is not correct");
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OtpAuthentication.class.equals(authentication);
	}

}
