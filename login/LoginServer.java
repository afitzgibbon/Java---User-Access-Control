package org.andy.login;

/*
 * An implementation of LoginServer is responsible for validating user login details which are
 * encapsulated in a LoginRequest. It returns a LoginResponse which will either confirm or deny
 * access to the caller. If the request is validated the appropriate User object will be 
 * encapsulated in the LoginResponse.
 */
public interface LoginServer {
	LoginResponse validate(LoginRequest request);
}