package org.andy.login;

import org.andy.security.Password;

/*
 * A LoginRequest is used by AbstractLogin to encapsulate login details and send them to an
 * implementation of LoginServer for validation.
 */
public class LoginRequest {
	private String username;
	private Password password;
	
	public LoginRequest(String username, Password password) {
		this.username = username;
		this.password = password;
	}
	
	public String getUsername() { return this.username; }
	public Password getPassword() { return this.password; }
}