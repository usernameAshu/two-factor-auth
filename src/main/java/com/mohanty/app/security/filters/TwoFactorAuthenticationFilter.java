package com.mohanty.app.security.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;

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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.mohanty.app.entity.Otp;
import com.mohanty.app.entity.Token;
import com.mohanty.app.repository.OtpRepository;
import com.mohanty.app.repository.TokenRepository;
import com.mohanty.app.security.authentications.OtpAuthentication;
import com.mohanty.app.security.authentications.UserCredentialsAuthentication;

import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class TwoFactorAuthenticationFilter extends OncePerRequestFilter {
	
	private final AuthenticationManager manager;
	private final OtpRepository otpRepository;
	private final TokenRepository tokenRepository;
	private final PasswordEncoder passwordEncoder;

	/**
	 * Step 1: Username & Password checking using the {@link UserCredentialsAuthentication}
	 * Step 2: if otp not present , then generate OTP
	 * Step 3: else if otp present, then check Username & otp using the {@link OtpAuthentication}
	 * Step 4: User receives a Authorization token 
	 * Step 5: User tries to access resources using that Authorization token 
	 */
	@Override
	protected void doFilterInternal(
			HttpServletRequest httpRequest, HttpServletResponse httpResponse, FilterChain chain)
			throws ServletException, IOException {
		
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
		
		//scenario: when user is logging in for first time & don't have the OTP
		if (otpCode.isPresent() && otpCode.get().isEmpty()) {

			Authentication authentication = new UserCredentialsAuthentication(username, password, grantedRoles);

			Authentication resultAuth = manager.authenticate(authentication);

			if (resultAuth.isAuthenticated()) {
				SecurityContextHolder.getContext().setAuthentication(authentication);

				// Step 2: Generate Otp here
				Otp otp = generateOtpForUser(username, httpResponse);
				otpRepository.save(otp);

			} else {
				System.out.println("Authentication failed");
				throw new BadCredentialsException("Authentication Failed");
			}
		} else {
			// scenario: user already entered credentials and has received the Otp
			// This is the 2nd step of authentication, to verify the Otp code received by
			// user
			// Step 3: Check Username & Otp
			// If username & otp is correct, then issue a Token
			Authentication otpAuth = new OtpAuthentication(username, otpCode.get(), grantedRoles);
			Authentication resultOtpAuth = manager.authenticate(otpAuth);
			if (resultOtpAuth.isAuthenticated()) {
				String responseToken = UUID.randomUUID().toString();
				httpResponse.addHeader("Auth-Token", responseToken);
				Token token = new Token();
				token.setUserName(username);
				token.setAuthToken(responseToken);
				secureStoreAuthToken(token);
			} else {
				throw new BadCredentialsException("Otp is not Correct. Resend the Otp.");
			}
		}
		
	}
	
	private void secureStoreAuthToken(Token token) {
		token.setAuthToken(passwordEncoder.encode(token.getAuthToken()));
		tokenRepository.save(token);
	}

	private Otp generateOtpForUser(String username, HttpServletResponse httpServletResponse) {
		Otp otp = null;
		String secretCode = String.valueOf(new Random().nextInt(9999)+1000);
		httpServletResponse.setHeader("otp", secretCode);
		Optional<Otp> otpuser = otpRepository.findOtpByUsername(username);
		
		if (!otpuser.isPresent()) {
			otp = new Otp();
			otp.setUsername(username);
			otp.setOtp(passwordEncoder.encode(secretCode));
		} else {
			otp = otpuser.get();
			otp.setOtp(passwordEncoder.encode(secretCode));
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


	/**
	 * Return true if you don't want to filter that request path
	 */
	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		// TODO Auto-generated method stub
		return !request.getServletPath().equals("/login");
	}

}
