package com.mohanty.app.security.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Filter class that will intercept the Request and Log the CSRF token 
 * @author 002L2N744
 *
 */
@Component
public class CsrfLoggingFilter extends OncePerRequestFilter {
	
	public static final Log LOG = LogFactory.getLog(CsrfLoggingFilter.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		CsrfToken token =  (CsrfToken)request.getAttribute("_csrf");
		LOG.debug("Csrf Token : "+ token.getToken());
		filterChain.doFilter(request, response);
	}


}
