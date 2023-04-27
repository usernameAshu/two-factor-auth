package com.mohanty.app.security.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.mohanty.app.security.authentications.CustomUserAuthenticationToken;

import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class CustomAuthenticationFilter implements Filter {
	
	private final AuthenticationManager manager;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
		
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse)response;
		
		String authHeader = httpRequest.getHeader("Authorization");
		String authType = httpRequest.getAuthType() ;
		
		Map<String,String> credentialsMap = base64Decoder(authHeader);
		//these parameters should be fetched from Request
		String username = credentialsMap.get("username");
		String password = credentialsMap.get("password");
		String role = httpRequest.getHeader("Roles");
		
		GrantedAuthority authority = () -> role;
		List<GrantedAuthority> grantedRoles = new ArrayList<>();
		grantedRoles.add(authority);
		
		Authentication authentication = new CustomUserAuthenticationToken(username, password, grantedRoles);
		
		Authentication resultAuth = manager.authenticate(authentication);
		
		if(resultAuth.isAuthenticated()) {
			SecurityContextHolder.getContext().setAuthentication(authentication);
			chain.doFilter(httpRequest, httpResponse);
		} else {
			System.out.println("Authentication failed");
			throw new BadCredentialsException("Authentication Failed");
		}
		
	}

	private Map<String,String> base64Decoder(String authHeader) {
		byte[] decodeBytes = Base64.getDecoder().decode(authHeader.split(" ")[1]);
		String decodedString = new String(decodeBytes);
		String username = decodedString.substring(0, decodedString.indexOf(":"));
		String password = decodedString.substring(decodedString.indexOf(":")+1);
		
		Map<String,String> credentialsMap = new HashMap<>();
		credentialsMap.put("username", username);
		credentialsMap.put("password", password);
		
		return credentialsMap;
		
	}

}
