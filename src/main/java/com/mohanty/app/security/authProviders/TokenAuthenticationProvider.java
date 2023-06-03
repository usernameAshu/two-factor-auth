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

import com.mohanty.app.entity.Token;
import com.mohanty.app.repository.TokenRepository;
import com.mohanty.app.security.authentications.TokenAuthentication;

import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class TokenAuthenticationProvider implements AuthenticationProvider {

	private final TokenRepository tokenRepository;
	private final PasswordEncoder passwordEncoder;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}
		
		String authTokenUser = authentication.getName() ;
		String authTokenCode = (String)authentication.getCredentials() ;
		Optional<Token> encodedOptToken = tokenRepository.findTokenByUserName(authTokenUser);
		
		if(encodedOptToken.isPresent() && !encodedOptToken.get().getAuthToken().isEmpty()) {
			String encodedToken = encodedOptToken.get().getAuthToken();
			List<GrantedAuthority> authorityList = new ArrayList<>();
			authorityList.add(() -> "USER");
			if(passwordEncoder.matches(authTokenCode, encodedToken)) {
				return new TokenAuthentication(authTokenUser, authTokenCode, authorityList);
			}
		} 
		
		throw new BadCredentialsException("Authorization Token error. Issue Auth token & login");
	}

	@Override
	public boolean supports(Class<?> authentication) {
		// TODO Auto-generated method stub
		return authentication.equals(TokenAuthentication.class);
	}

}
