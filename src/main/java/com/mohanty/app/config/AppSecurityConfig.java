package com.mohanty.app.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Primary;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;

import com.mohanty.app.repository.UsersRepository;
import com.mohanty.app.security.authProviders.OtpAuthenticationProvider;
import com.mohanty.app.security.authProviders.TokenAuthenticationProvider;
import com.mohanty.app.security.authProviders.UserCredentialsAuthenticationProvider;
import com.mohanty.app.security.filters.CsrfLoggingFilter;
import com.mohanty.app.security.filters.TokenAuthenticationFilter;
import com.mohanty.app.security.filters.TwoFactorAuthenticationFilter;
import com.mohanty.app.security.service.CustomUserDetailsService;

@Configuration
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {

	private UserCredentialsAuthenticationProvider usernamePasswordAuthProvider;
	private OtpAuthenticationProvider otpAuthenticationProvider;
	private TokenAuthenticationProvider tokenAuthenticationProvider;
	private TwoFactorAuthenticationFilter twoFactorFilter;
	private TokenAuthenticationFilter tokenFilter;
	private CsrfLoggingFilter csrfLoggingFilter;

	public AppSecurityConfig(
			@Lazy TwoFactorAuthenticationFilter filter, 
			@Lazy TokenAuthenticationFilter tokenFilter,
			@Lazy UserCredentialsAuthenticationProvider usernamePasswordAuthProvider,
			@Lazy OtpAuthenticationProvider otpAuthenticationProvider,
			@Lazy TokenAuthenticationProvider tokenAuthenticationProvider,
			@Lazy CsrfLoggingFilter csrfLoggingFilter
			) {
		
		this.twoFactorFilter = filter;
		this.tokenFilter = tokenFilter;
		this.csrfLoggingFilter = csrfLoggingFilter;
		this.usernamePasswordAuthProvider = usernamePasswordAuthProvider;
		this.otpAuthenticationProvider = otpAuthenticationProvider;
		this.tokenAuthenticationProvider = tokenAuthenticationProvider;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.addFilterAt(twoFactorFilter, BasicAuthenticationFilter.class)
			.addFilterAfter(tokenFilter, BasicAuthenticationFilter.class)
			.addFilterAfter(csrfLoggingFilter, CsrfFilter.class);
		http.httpBasic();
		
		/**
		 * CSRF : Cross Site Request Forgery 
		 * When hacker wants to do any mutable operations via an external link
		 * hacker will send a email, which will trigger any internal POST/PUT call to the app
		 * So, spring security assigns a csrf token for any Mutable requests, if any call doesn't have that csrf token,
		 * that request gets rejected 
		 * Mention the path where csrf has to be disabled 
		 */
//		http.csrf().disable(); // Not a good practice to disable CSRF protection 
		http.csrf( customizer -> {
			customizer.ignoringAntMatchers("/csrfdisabled/**");
		});

		/**
		 * To allow the post call (add user) happen without authentication All other
		 * endpoints are secured
		 */
		http.authorizeHttpRequests().antMatchers("/user").permitAll().anyRequest().authenticated();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(usernamePasswordAuthProvider)
			.authenticationProvider(otpAuthenticationProvider)
			.authenticationProvider(tokenAuthenticationProvider);
	}

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		// TODO Auto-generated method stub
		return super.authenticationManagerBean();
	}
	
	/**
	 * Using a manager instead of a User-details-service helps to manage the user
	 * with create, update, delete functionalities
	 * 
	 * @param datasource
	 * @return
	 */
	@Bean
	@Primary
	JdbcUserDetailsManager userDetailsManager(DataSource datasource) {
		return new JdbcUserDetailsManager(datasource);
	}
	
	/**
	 * When we use a UserDetailManager, it overwrites the functionality of a UserDetailService
	 * so we have to mark any one of the bean as @Primary 
	 * @param repository
	 * @return
	 */
	@Bean
	CustomUserDetailsService customUserDetailsService(UsersRepository repository) {
		return new CustomUserDetailsService(repository, passwordEncoder());
	}
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	/**
	 * This sets the Spring to make the SecurityContext available throughout threads 
	 * in the application
	 * @return
	 */
	@Bean
	public InitializingBean initializingBean() {
		return () -> {
			SecurityContextHolder.setStrategyName(
					SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
		};
	}

}
