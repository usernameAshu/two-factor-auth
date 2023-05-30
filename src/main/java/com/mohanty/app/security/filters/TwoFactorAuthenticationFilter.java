package com.mohanty.app.security.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

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

import com.mohanty.app.entity.Otp;
import com.mohanty.app.repository.OtpRepository;
import com.mohanty.app.security.authentications.OtpAuthentication;
import com.mohanty.app.security.authentications.UserCredentialsAuthentication;

import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class TwoFactorAuthenticationFilter implements Filter {
	
	private final AuthenticationManager manager;
	private final OtpRepository otpRepository;

	/**
	 * Step 1: Username & Password checking using the {@link UserCredentialsAuthentication}
	 * Step 2: if otp not present , then generate OTP
	 * Step 3: Username & otp using the {@link OtpAuthentication}
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
		
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse)response;
		
		//Step 1 : Username & Password authentication 
		String authHeader = httpRequest.getHeader("Authorization");
		String authType = httpRequest.getAuthType() ;
		
		Map<String,String> credentialsMap = base64Decoder(authHeader);
		//these parameters should be fetched from Request
		String username = credentialsMap.get("username");
		String password = credentialsMap.get("password");
		String role = httpRequest.getHeader("Roles");
		Optional<String> otpCode = Optional.of(httpRequest.getHeader("otp"));
		
		GrantedAuthority authority = () -> role;
		List<GrantedAuthority> grantedRoles = new ArrayList<>();
		grantedRoles.add(authority);
		
		//scenario: when user is logging in for first time
		if (otpCode.isPresent() && otpCode.get().isEmpty()) {

			Authentication authentication = new UserCredentialsAuthentication(username, password, grantedRoles);

			Authentication resultAuth = manager.authenticate(authentication);

			if (resultAuth.isAuthenticated()) {
				SecurityContextHolder.getContext().setAuthentication(authentication);

				// Step 2: Generate Otp here
				Otp otp = generateOtpForUser(username);
				httpResponse.setHeader("otp", otp.getOtp());
				otpRepository.save(otp);
				chain.doFilter(httpRequest, httpResponse);

			} else {
				System.out.println("Authentication failed");
				throw new BadCredentialsException("Authentication Failed");
			}
		} else {
			//scenario: user already entered credentials and has received the Otp 
			//This is the 2nd step of authentication, to verify the Otp code received by user
			//Step 3: Check Username & Otp
			Authentication otpAuth = new OtpAuthentication(username, otpCode.get(), grantedRoles);
			Authentication resultOtpAuth = manager.authenticate(otpAuth);
			if(resultOtpAuth.isAuthenticated()) {
			httpResponse.addHeader("Auth-status", "2 factor authentication success");
			} else {
				throw new BadCredentialsException("Otp is not Correct. Resend the Otp.");
			}
		}
		
	}
	
	private Otp generateOtpForUser(String username) {
		Otp otp = null;
		int secretCode = new Random().nextInt(9999)+1000;
		Optional<Otp> otpuser = otpRepository.findOtpByUsername(username);
		if (!otpuser.isPresent()) {
			otp = new Otp();
			otp.setUsername(username);
			otp.setOtp(String.valueOf(secretCode));
		} else {
			otp = otpuser.get();
			otp.setOtp(String.valueOf(secretCode));
		}
		return otp;
	}

	/**
	 * Decoding the "Basic 1234xyz" from auth header into username & password using base64 {@link Base64.Decoder}
	 * @param authHeader
	 * @return
	 */
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
