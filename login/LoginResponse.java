package org.andy.login;

import org.andy.user.User;

 /* 
  * A LoginResponse is sent from a LoginServer implementation to an AbstractLogin object in 
  * response to a LoginRequest. If the login is validated, isValidated() will retrun true and
  * getUser() will return the appropriate User object. If isValidated() returns false,
  * getUser() will return null.
  */
public class LoginResponse {
	private boolean validated;
	private User user;
	
	public LoginResponse(boolean validated) { this(validated, null); }
	public LoginResponse(boolean validated, User user) {
		this.validated = validated;
		this.user = user;
	}
	
	boolean isValidated() { return validated; }
	User getUser() { return user; }
}