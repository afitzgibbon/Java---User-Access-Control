package org.andy.login;

import org.andy.user.User;

 /* 
  * A LoginResponse is sent from a LoginServer implementation to an AbstractLogin object in 
  * response to a LoginRequest. If the login is validated, isValidated() will retrun true and
  * getUser() will return the appropriate User object. If isValidated() returns false,
  * getUser() is still returned and this is so the recipient can check the password lock.
  */
public class LoginResponse {
	private boolean isValidated;
	private User user;
	
	public LoginResponse(boolean isValidated) { this(isValidated, null); }
	public LoginResponse(boolean isValidated, User user) {
		this.isValidated = isValidated;
		this.user = user;
	}
	
	boolean isValidated() { return this.isValidated; }
	User getUser() { return this.user; }
}