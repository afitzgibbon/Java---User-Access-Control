package org.andy.user;

import org.andy.security.Password;

/*
 * A User object encapsulates user details. Its equality is determined by a username and
 * it is Comparable which enables sorting by name followed by username.
 */
public class User implements Comparable<User> {
	private String name;
	private String username;
	private Password password;
	
	public User(String username, Password password) {
		this("", username, password);
	}
	public User(String name, String username, Password password) {
		setName(name);
		setUsername(username);
		setPassword(password);
	}
	
	public int compareTo(User other) {
		int res = this.getName().compareTo(other.getName());
		
		if (res < 0) return -1;
		else if (res > 0) return 1;
		else return this.getUsername().compareTo(other.getUsername());
	}
	
	public boolean equals(User other) {
		return this.getUsername().equals(other.getUsername());	
	}
	
	public String getName() { return name; }
	public Password getPassword() { return password; }
	public String getUsername() { return username; }
	
	public void setName(String name) { this.name = name; }
	public void setPassword(Password password) { this.password = password; }
	public void setUsername(String username) { this.username = username; }
	
	public void print() { System.out.println(String.format("%-20s%s", getName(), getUsername())); }
	
	public String toString() { return getName(); }
}