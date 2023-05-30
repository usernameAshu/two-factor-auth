package com.mohanty.app.config;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.mohanty.app.repository.UsersRepository;
import com.mohanty.app.security.authProviders.OtpAuthenticationProvider;
import com.mohanty.app.security.authProviders.UserCredentialsAuthenticationProvider;
import com.mohanty.app.security.filters.TwoFactorAuthenticationFilter;
import com.mohanty.app.security.service.CustomUserDetailsService;


@Configuration
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {

	private UserCredentialsAuthenticationProvider usernamePasswordAuthProvider;
	private OtpAuthenticationProvider otpAuthenticationProvider;
	private TwoFactorAuthenticationFilter filter;

	public AppSecurityConfig(@Lazy UserCredentialsAuthenticationProvider usernamePasswordAuthProvider,
			@Lazy TwoFactorAuthenticationFilter filter, @Lazy OtpAuthenticationProvider otpAuthenticationProvider) {
		this.usernamePasswordAuthProvider = usernamePasswordAuthProvider;
		this.otpAuthenticationProvider = otpAuthenticationProvider;
		this.filter = filter;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.addFilterAt(filter, BasicAuthenticationFilter.class);
		http.httpBasic();
		http.csrf().disable(); // Disabling to implement CSRF tokens

		/**
		 * To allow the post call (add user) happen without authentication All other
		 * endpoints are secured
		 */
		http.authorizeHttpRequests().antMatchers("/user").permitAll().anyRequest().authenticated();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(usernamePasswordAuthProvider)
			.authenticationProvider(otpAuthenticationProvider);
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

}
