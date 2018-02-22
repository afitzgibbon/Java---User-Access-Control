package org.andy.test;

import java.util.Arrays;
import org.andy.security.Password;
import org.andy.user.User;

public class UserPrivilegeTest {
	public static void main(String[] args) {
		char[] plainText = new String("one2Three!").toCharArray();
		User user = new User("Andy Fitzgibbon", "andy.fitzgibbon", new Password(plainText));
		
		// Test - check initial privileges
		// Result: [STANDARD]
		// Test Passed
		System.out.println(Arrays.toString(user.getPrivileges()));
		
		// Test - add duplicate privilege
		// Result: [STANDARD]
		// Test Passed
		user.addPrivilege(User.Privilege.STANDARD);
		System.out.println(Arrays.toString(user.getPrivileges()));
		
		// Test - try remove the default STANDARD privilege
		// Result: [STANDARD]
		// Test Passed
		user.removePrivilege(User.Privilege.STANDARD);
		System.out.println(Arrays.toString(user.getPrivileges()));
		
		// Test - add a new privilege: USER_ADMIN
		// Result: [STANDARD, USER_ADMIN]
		// Test Passed
		user.addPrivilege(User.Privilege.USER_ADMIN);
		System.out.println(Arrays.toString(user.getPrivileges()));
		
		// Test - check if user has privilege USER_ADMIN
		// Result: ture
		// Test Passed
		System.out.println(user.hasPrivilege(User.Privilege.USER_ADMIN));
		
		// Test - remove the USER_ADMIN privilege
		// Result: [STANDARD]
		// Test Passed
		user.removePrivilege(User.Privilege.USER_ADMIN);
		System.out.println(Arrays.toString(user.getPrivileges()));
		
		// Test - check if user has privilege USER_ADMIN
		// Result: false
		// Test Passed
		System.out.println(user.hasPrivilege(User.Privilege.USER_ADMIN));
		
		// Test - remove privilege that isn't there
		// Result: [STANDARD] (no exception which is fine)
		// Test Passed
		user.removePrivilege(User.Privilege.USER_ADMIN);
		System.out.println(Arrays.toString(user.getPrivileges()));
	}
}