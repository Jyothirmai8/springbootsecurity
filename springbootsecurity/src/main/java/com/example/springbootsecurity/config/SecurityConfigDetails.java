package com.example.springbootsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfigDetails extends WebSecurityConfigurerAdapter {

	// for authentication 
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("jyothi").password("jyothi").roles("USER");
		auth.inMemoryAuthentication().withUser("kamal").password("kamal").roles("ADMIN");
	}
	
	// for authorization
	public void configure(HttpSecurity http) throws Exception{
		http.antMatcher("/**").authorizeRequests().anyRequest().hasRole("USER")
		.and().formLogin().loginPage("/login.jsp")
		.failureUrl("/loginfail.jsp")
		.loginProcessingUrl("/logincontroller")
		.permitAll().and().logout()
		.logoutSuccessUrl("/login.jsp");
		
	}
	
}
