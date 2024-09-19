package com.Spring.learn_Spring_Security.config;

import java.util.Objects;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;

public class ShashwenthAuthenticationProvider implements AuthenticationProvider {

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		var name=authentication.getName();
		if(Objects.equals(name, "Shashwenth")) {
			var shashwenth= User.withUsername("Shashwenth")
					.password("default")
					.roles("user","admin")
					.build();
			return UsernamePasswordAuthenticationToken.authenticated(authentication, null, shashwenth.getAuthorities());
		}
		return null;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
