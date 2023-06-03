package com.mohanty.app.security.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.mohanty.app.exceptions.TokenNotFoundException;
import com.mohanty.app.security.authentications.TokenAuthentication;

import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {
	
	private final AuthenticationManager authenticationManager;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		String authUser = request.getHeader("username");
		String authToken = request.getHeader("token");
		if(authToken == null || authUser == null) {
			throw new TokenNotFoundException("Auth token & user-name is required to login");
		}
		
		List<GrantedAuthority> authorityList = new ArrayList<>();
		authorityList.add(() -> "USER");
		
		Authentication authInput = new TokenAuthentication(authUser, authToken, authorityList);
		
		Authentication resultAuth = authenticationManager.authenticate(authInput);
		
		if(resultAuth.isAuthenticated()) {
			SecurityContextHolder.getContext().setAuthentication(resultAuth);
			filterChain.doFilter(request, response);
		}
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		// TODO Auto-generated method stub
		return request.getServletPath().equals("/login");
	}
	
	

}
