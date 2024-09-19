package com.Spring.learn_Spring_Security.config;

import java.io.IOException;
import java.util.Collections;
import java.util.Objects;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CustomFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		if(!Collections.list(request.getHeaderNames()).contains("x-custom")) {
			filterChain.doFilter(request, response);
			return;
		}
		
		if (!Objects.equals(request.getHeader("x-custom"), "enter")) {
			response.setStatus(HttpStatus.FORBIDDEN.value());
			response.getWriter().write("This is Not allowed");
			return;
		}
		var auth=new CustomAuthenticationToken();
		var newContext=SecurityContextHolder.createEmptyContext();
		newContext.setAuthentication(auth);
		SecurityContextHolder.setContext(newContext);
		
		filterChain.doFilter(request, response);
		
	}

}
