package com.Spring.learn_Spring_Security.config;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

public class CustomAuthenticationToken extends AbstractAuthenticationToken {

	public CustomAuthenticationToken() {
		super(AuthorityUtils.createAuthorityList("ROLE_CUSTOM"));
		// TODO Auto-generated constructor stub
	}

	@Override
	public Object getCredentials() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Object getPrincipal() {
		// TODO Auto-generated method stub
		return "custom filter";
	}
	
	@Override
	public boolean isAuthenticated() {
		return true;
	}

	@Override
	public void setAuthenticated(boolean authenticated) {
		throw new RuntimeException("YOu are not custom entry");
	}
	
	
	

}
