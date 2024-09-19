package com.Spring.learn_Spring_Security.controllers;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HelloWorldControllerForOrder1 {

	@GetMapping(path = "/hello-world")
	public String HelloWorld(Authentication authentication) {
//		System.out.println("GetPrincipal ToString");
//		System.out.println(authentication.getPrincipal().toString());
//		System.out.println("Authentication Tostring");
//		System.out.println(authentication.toString());
//		System.out.println("get class in authentication");
//		System.out.println(authentication.getPrincipal().getClass());
		return "Hello World in /api";
	}
	
	
	@GetMapping(path = "/private-world")
	public String HelloPrivateWorld(Authentication authentication) {
//		System.out.println("GetPrincipal ToString");
//		System.out.println(authentication.getPrincipal().toString());
//		System.out.println("Authentication Tostring");
//		System.out.println(authentication.toString());
//		System.out.println("get class in authentication");
//		System.out.println(authentication.getPrincipal().getClass());
		return "Hello Private World in /api";
	}
	
}
