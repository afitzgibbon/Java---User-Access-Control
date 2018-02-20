package org.andy.ui.console;

import java.util.Arrays;
import org.andy.login.AbstractLogin;
import org.andy.login.LoginServer;
import org.andy.security.Password;
import org.andy.user.User;

/*
 * ConsoleLogin is a simple implementation of AbstractLogin which gets user input via the
 * console and handles login success, failure and password expired scenarios. It requires 
 * an implementation of a LoginServer to pass to its superclass.
 */
public class ConsoleLogin extends AbstractLogin {
	public ConsoleLogin(LoginServer server) { super(server); }
	
	public void getUserInput() {
		System.out.print("\nUsername: ");
		super.setUsername(System.console().readLine());
		
		System.out.print("Password: ");
		super.setPassword(new Password(System.console().readPassword()));
	}
	
	private void changePassword() {
		boolean isValid = false;
		
		do {
			System.out.print("Current Password: ");
			char[] plainText = System.console().readPassword();
			Password password = new Password(plainText);
			
			if (password.equals(super.getUser().getPassword()))
				isValid = true;
			else System.out.println("\nIncorrect password entered!");
		}
		while (!isValid);
		
		isValid = false;
		do {
			try {
				System.out.print("New Password    : ");
				char[] plainText = System.console().readPassword();
			
				System.out.print("Confirm Password: ");
				char[] plainText2 = System.console().readPassword();
			
				if (Arrays.equals(plainText, plainText2)) {
					Arrays.fill(plainText2, '\u0000'); // clear confirmation char[], Password clears the other
					super.getUser().getPassword().setIsNew(true); // flag this password as a new password
					super.getUser().getPassword().change(plainText); // run SecurityPolicy rules on new password
					
					// if no SecurityExceptions are thrown...
					isValid = true;
				}
				else System.out.println("\nPasswords do not match!");
			}
			catch (SecurityException ex) {
				System.out.println(ex.getMessage());
			}
		} while (!isValid);
	}
	
	public void onFailure() {
		System.out.println("Username or password is incorrect!");
	}
	
	public void onPasswordExpired() {
		System.out.println("\nYour password has expired and needs to be changed...");
		this.changePassword();
	}
	
	/*
	 * The prupose of a login-check is to validate a user and then pass control on to an 
	 * underlying application. This method is the entry point to such an application. It is
	 * important to retrieve and pass on the validated User object in case of changes such
	 * as password / privileges / user info / etc... After the session is complete the User
	 * object should then be persisted, if needed, so it can be resored to its active state.
	 */
	public void onSuccess() {
		User user = super.getUser(); 
		System.out.println("Login Successful! Welcome " + user.getName() + "!!");
		// MyApp myApp = new MyApp(user);
	}
}