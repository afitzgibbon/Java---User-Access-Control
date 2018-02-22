package org.andy.user;

import java.util.ArrayList;
import org.andy.security.Password;

/*
 * A User object encapsulates user details. Its equality is determined by a username and
 * it is Comparable which enables sorting by name followed by username. Every user by 
 * default will have STANDARD privilege rights only.
 */
public class User implements Comparable<User> {
	// This enum defines the privilege rights a user can have.
	public static enum Privilege { STANDARD, USER_ADMIN };
	
	private ArrayList<Privilege> privileges;
	private String name;
	private String username;
	private Password password;
	
	public User(String username, Password password) {
		this("", username, password);
	}
	public User(String name, String username, Password password) {
		this.privileges = new ArrayList<User.Privilege>();
		this.setName(name);
		this.setUsername(username);
		this.setPassword(password);
		this.addPrivilege(User.Privilege.STANDARD);
	}
	
	/* This method adds a privilete if it doesn't already exist. */
	public void addPrivilege(User.Privilege privilege) {
		for (User.Privilege p : privileges) {
			if (privilege.equals(p))
				return;
		}
		privileges.add(privilege);
	}
	
	/* A User is compared on the user's name followed by username. */
	public int compareTo(User other) {
		int res = this.getName().compareTo(other.getName());
		
		if (res < 0) return -1;
		else if (res > 0) return 1;
		else return this.getUsername().compareTo(other.getUsername());
	}
	
	/* This method returns an array of this users privileges. */
	public User.Privilege[] getPrivileges() {
		return privileges.toArray(new User.Privilege[privileges.size()]);
	}
	
	/* User uniqueness and equality is based on the username. */
	public boolean equals(User other) {
		return this.getUsername().equals(other.getUsername());	
	}
	
	public String getName() { return name; }
	public Password getPassword() { return password; }
	public String getUsername() { return username; }
	
	/* This method returns true if this user has a specified privilege. */
	public boolean hasPrivilege(User.Privilege privilege) { 
		for (User.Privilege p : privileges) {
			if (privilege.equals(p))
				return true;
		}
		return false;	
	}
	
	/* This method will remove the specified privilege if it exists. It will
	 * however not remove the STANDARD privilege which is a default for every
	 * user.
	 */
	public void removePrivilege(User.Privilege privilege) {
		if (privilege.equals(User.Privilege.STANDARD))
			return;
		
		for (User.Privilege p : privileges) {
			if (privilege.equals(p)) {
				privileges.remove(p);
				break;
			}
		}
	}
	
	public void setName(String name) { this.name = name; }
	public void setPassword(Password password) { this.password = password; }
	public void setUsername(String username) { this.username = username; }
	
	public void print() { System.out.println(String.format("%-20s%s", getName(), getUsername())); }
	
	public String toString() { return getName(); }
}