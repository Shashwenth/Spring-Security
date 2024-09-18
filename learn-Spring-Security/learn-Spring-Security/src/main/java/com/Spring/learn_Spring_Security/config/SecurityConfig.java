package com.Spring.learn_Spring_Security.config;

import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
			   .authorizeHttpRequests(
					   (auth) -> {
						   auth.requestMatchers("/hello-world").permitAll();
						   auth.anyRequest().authenticated();
					   		}
					   )
			   .formLogin(Customizer.withDefaults())
			   .logout(l->l.logoutSuccessUrl("/hello-world"))
			   .addFilterBefore(new CustomFilter(),AuthorizationFilter.class)
			   .httpBasic(Customizer.withDefaults())
			   .build();
		
	}
	
	@Bean
	UserDetailsService userDetailsService() {
		User user= (User) User.withUsername("user")
					.password("{noop}user")
					.roles("user")
					.build();
		
		User admin= (User) User.withUsername("admin")
				.password("{noop}admin")
				.roles("admin")
				.build();
		
		return new InMemoryUserDetailsManager(user,admin);
	}
	
	@Bean
	ApplicationListener<AuthenticationSuccessEvent> successListener() {
		return event -> {
			System.out.println("[%s] %s".formatted(
					event.getAuthentication().getClass().getSimpleName(),
					event.getAuthentication().getName()
			));
		};
	}
	
}
