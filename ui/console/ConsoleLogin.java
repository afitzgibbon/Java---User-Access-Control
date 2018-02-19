package org.andy.ui.console;

import java.io.Console;
import org.andy.login.AbstractLogin;
import org.andy.login.LoginServer;
import org.andy.security.Password;
import org.andy.user.User;

/*
 * ConsoleLogin is a simple implementation of AbstractLogin which reads login details
 * from the console screen and displays success or failure messages back. It requires 
 * an implementation of a LoginServer.
 */
public class ConsoleLogin extends AbstractLogin {
	public ConsoleLogin(LoginServer server) { super(server); }
	
	public void getUserInput() {
		Console con = System.console();
		
		System.out.print("\nUsername: ");
		super.setUsername(con.readLine());
		
		System.out.print("Password: ");
		super.setPassword(new Password(con.readPassword()));
	}
	
	public void onFailure() {
		System.out.println("Username or password is incorrect!");
	}
	
	public void onSuccess() {
		User user = super.getUser();
		System.out.println("Login Successful! Welcome " + user.getName() + "!!");
	}
}