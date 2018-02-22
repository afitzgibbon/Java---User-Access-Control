package org.andy.test;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import org.andy.security.Password;

public class PasswordTest {
	
	public static void main(String[] args) {
		// Note: I'm using String.toCharArray() to get a char[] to pass to Password.
		// In practice a String would not be used.
		
		// Test - turn off strict mode (should not encrypt password)
		// Result: one2Three!
		// Test Passed
		char[] in = new String("one2Three!").toCharArray();
		Password.getSecurityPolicy().setStrict(false); // turn strict off
		System.out.println(createPassword(in));
		Password.getSecurityPolicy().setStrict(true); // turn strict back on
		
		// Test - 1 char password
		// Result: Warning that password is too short
		// Test Psased
		in = new String("x").toCharArray();
		System.out.println(createPassword(in));
		
		// Test - 8 char password all 'x's
		// Result: Warning that no digit is present
		// Test Passed
		in = new String("xxxxxxxx").toCharArray();
		System.out.println(createPassword(in));
		
		// Test - add a digit
		// Result: Warning that no special char is present
		// Test Passed
		in = new String("xxxxxxxx2").toCharArray();
		System.out.println(createPassword(in));
		
		// Test - add a special character
		// Result: Warning that no upper case is used
		// Test Passed
		in = new String("xxxxxxxx2!").toCharArray();
		System.out.println(createPassword(in));
		
		// Test - replace lower case with upper
		// Result: Warning that no lower case is used
		// Test Passed
		in = new String("XXXXXXXX2!").toCharArray();
		System.out.println(createPassword(in));
		
		// Test - replace with mix of upper and lower
		// Result: 64 char hex excrypted String
		// Test Passed
		in = new String("one2Three!").toCharArray();
		System.out.println(createPassword(in));
		
		
		// For the next text I'm tuning off encryption to enabel the history
		// to be filled with plaintext passwords. This feature should only be
		// used in testing. I will also reduce the history size to 2.
		try {
			Password.getSecurityPolicy().setEncryptionAlgorithm(null);
		} catch (NoSuchAlgorithmException ex) {} // ignore exception
		Password.getSecurityPolicy().setHistoryCount(2);
		
		in = new String("one2Three!").toCharArray();
		Password password = new Password(in, true); // set initial password to 123
		in = new String("two3Four!").toCharArray();
		changePassword(password, in); // change password to 234, 123 is now in history
		
		// Test - try to change password to 'one2Three!'
		// Result: Warning that it is a recient password
		// Test Passed
		in = new String("one2Three!").toCharArray();
		changePassword(password, in);
		
		// Test - try to change password to 'two3Four!'
		// Result: Warning that it is a recient password
		// Test Passed
		in = new String("two3Four!").toCharArray();
		changePassword(password, in);
		
		// Test - try to change password to 'three4Five!'
		// Result: three4Five!
		// Test Passed
		in = new String("three4Five!").toCharArray();
		changePassword(password, in);
		System.out.println(password);
		
		
		// Update the security policy to dismiss history
		password.getSecurityPolicy().setHistoryCount(0);
		
		// Test - try to change password to itself 'three4Five!'
		// Result: three4Five! 
		// Test Passed
		in = new String("three4Five!").toCharArray();
		changePassword(password, in);
		System.out.println(password);
		
		
		// Set up Password as if it were persisted from storage. Will leave encryption
		// off but will set historyCount back to default of 3.
		password.getSecurityPolicy().setHistoryCount(3);
		
		String[] history = {
			"one2Three!",
			"two3Four!"
		};
		
		String secret = "three4Five!";		
		
		// Set the creation date to 91 days ago, default expires on 90 days
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.DATE, -91); // set date offset of -91 days
		Date date = cal.getTime();
		
		boolean isLocked = false;
		
		// Test - check expiry date
		// Result: true
		// Test Passed
		password = new Password(secret, history, date, isLocked);
		System.out.println("expired=" + password.isExpired());
		
		// Test - check expiry date for now
		// Result: false
		// Test Passed
		password = new Password(secret, history, new Date(), isLocked);
		System.out.println("expired=" + password.isExpired());
		
		// Test - check password lock
		// Result: false, false, true
		// Test Passec
		password.equals("one");
		System.out.println("locked=" + password.isLocked());
		password.equals("one");
		System.out.println("locked=" + password.isLocked());
		password.equals("one");
		System.out.println("locked=" + password.isLocked());
	}
	
	private static void changePassword(Password password, char[] plainText) {
		try {
			password.change(plainText);
		}
		catch (SecurityException ex) {
			System.out.println(ex.getMessage());
		}
	}
	
	private static String createPassword(char[] plainText) {
		try {
			return new Password(plainText, true).getSecret();
		}
		catch (SecurityException ex) {
			return ex.getMessage();
		}
	}
}