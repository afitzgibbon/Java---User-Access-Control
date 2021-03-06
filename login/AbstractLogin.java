package org.andy.login;

import org.andy.security.Password;
import org.andy.user.User;

/*
 * AbstractLogin sets up the protocol to communicate with a LoginServer via LoginRequest and 
 * LoginResponse. This is transparent to subclasses and therefore they not be concerned about 
 * it. Subclasses must provide implementation for the following:
 *
 * 1. getUserInput()
 *    - how to obtain the user input is defined here (swing/fx/console)
 * 2. onFailure()
 *    - define what happens when a login attempt fails
 * 3. onPasswordExpired()
 *    - define what happens when 'this' encounters an expired password
 * 4. onPasswordLocked()
 *    - define what happens when 'this' encounters a locked password
 * 5. onSuccess()
 *    - define what happens when a login succeeds
 *
 * By default an AbstractLogin terminates after 3 incorrect login attempts but this can be 
 * changed by the subclass.
 */
public abstract class AbstractLogin {
	private static final int PERMITTED_ATTEMPTS = 3;
	private Password password;
	private String username;
	private User user;
	private boolean isValid;
	private int permittedAttempts;
	
	public AbstractLogin(LoginServer server) {
		int loginCount = 0;
		this.setPermittedAttempts(PERMITTED_ATTEMPTS);
		
		do {			
			this.getUserInput();
			
			LoginRequest request = new LoginRequest(this.getUsername(), this.getPassword());
			LoginResponse response = server.validate(request);
			
			if (response.isValidated()) {
				this.setUser(response.getUser()); // set User for subclass
				
				// Subclass needs to take action if a password has expired
				if (this.getUser().getPassword().isExpired())
					this.onPasswordExpired();
		
				// Subclass needs to take action after password validation has succeeded
				this.onSuccess();			
				break;
			}
			// Login has failed, subclass needs to take action here. It will fail for
			// two reasons, either an incorrect username/password combination or if 
			// there is a lock on the password. If there is a lock a User object will 
			// be returned otherwise it will be null.
			else {
				try {
					if (response.getUser().getPassword().isLocked()) // throws ex if user=null
						this.onPasswordLocked();
				}
				catch (NullPointerException ex) {
					this.onFailure();
				}
			}
		}
		while (++loginCount < this.getPermittedAttempts());
	}

	protected abstract void getUserInput();
	protected abstract void onFailure();
	protected abstract void onPasswordExpired();
	protected abstract void onPasswordLocked();
	protected abstract void onSuccess();
	
	private Password getPassword() { return this.password; }
	private int getPermittedAttempts() {return this.permittedAttempts; }
	protected User getUser() { return this.user; }
	private String getUsername() { return this.username; }
	
	protected void setPassword(Password password) { this.password = password; }
	protected void setPermittedAttempts(int permittedAttempts) { this.permittedAttempts = permittedAttempts; }
	protected void setUser(User user) { this.user = user; }
	protected void setUsername(String username) { this.username = username; }
}