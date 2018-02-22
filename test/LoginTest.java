package org.andy.test;

import java.util.Calendar;
import java.util.Date;
import org.andy.login.LoginServer;
import org.andy.login.LoginRequest;
import org.andy.login.LoginResponse;
import org.andy.security.Password;
import org.andy.ui.console.ConsoleLogin;
import org.andy.user.User;

public class LoginTest {
	public static void main(String[] args) {
		Password password = null;
		
		// Test - verify expiry function
		// Uncomment the below block which simulates a persisted password. The
		// creation date of the password is set to -91 days which should force
		// a password change at login.
		//
		// Test Passed
		/*
		String secret = "one2Three!";
				
		String[] history = {
			"two3Four!",
			"three4Five!"
		};
				
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.DATE, -91);
		Date date = cal.getTime();
				
		try {
			Password.getSecurityPolicy().setEncryptionAlgorithm(null);
		} catch (Exception ex) {}
		
		boolean isLocked = false;
		
		password = new Password(secret, history, date, isLocked);
		//*/
		
		// Test - verify locking function
		// Uncomment the below block which is the same as above but this time the
		// password has been persisted as locked. At login the user should be 
		// informed that the password is locked.
		//
		// Test Passed
		/*
		String secret = "one2Three!";
				
		String[] history = {
			"two3Four!",
			"three4Five!"
		};
				
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.DATE, -91);
		Date date = cal.getTime();
				
		try {
			Password.getSecurityPolicy().setEncryptionAlgorithm(null);
		} catch (Exception ex) {}
		
		boolean isLocked = true;
		
		password = new Password(secret, history, date, isLocked);
		//*/
		
		// Test - three incorrect login attempts
		// Uncomment the below block which creates a new password which is not 
		// expired or has no failed login attempts. Three incorrect logins should
		// lock the password.
		//
		// Test Passed
		/*
			password = new Password(new String("one2Three!").toCharArray());
		//*/
		
		
		// The user object required for the above tests
		User user = new User("Andy Fitzgibbon", "andy.fitzgibbon", password);
		
		/*
		 * Create a simple implementation of a LoginServer. It requires validating
		 * a LoginResponse and returning a LoginResponse.
		 */
		ConsoleLogin login = new ConsoleLogin(new LoginServer() {
			public LoginResponse validate(LoginRequest request) {  
				// Check this username against the request one.
				if (user.getUsername().equals(request.getUsername())) {
					// Username is valid, check if this password is locked. For this
					// check the request password is irrelevant.
					if (user.getPassword().isLocked()) {
						return new LoginResponse(false, user);
					} 
					// Password is not locked, so now check it
					else {
						// Username & password are both valid
						if (user.getPassword().equals(request.getPassword())) {
							return new LoginResponse(true, user);
						}
						// Need to check the password lock as it may have been
						// triggered by the above 'equals' check.
						else if (user.getPassword().isLocked()) {
							return new LoginResponse(false, user);
						}
					}
				}
				
				// This will return if the request username doesn't exits or if the
				// above password check fails. Therefore the request username or
				// password is incorrect.
				return new LoginResponse(false);
			}
		});
	}
}