package org.andy.security;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Date;

/*
 * A Password object is used to store a password which is governed by a SecurityPolicy. By default 
 * SecurityPolicy is set to strict which enforces password rules and encryption. The plain text
 * password is stored in a character array and it's contents are destroyed once a secret password 
 * is created. A Password object can be created in one of three ways;
 * 
 * 1. Password password = new Password(plainText)
 *    - this constructor is used to create a temporary password that can be compared to a real
 *      Password and verified ie. at login. This password bypasses all security checks and will
 *      therefore not throw any exceptions.
 * 2. Password password = new Password(plainText, isNew)
 *    - this constructor is used when creating a password for the first time. ensure boolean
 *      value for isNew is set to true.
 * 3. Password password = new Password(secret, history, creationDate)
 *    - this constructor is used when loading a password from some sort of persistence.
 * 
 * The SecurityPolicy can be disabled, which may be useful for testing purposes but
 * be warned that this feature will store the password in its plain text form. The following 
 * call will accomplish this;
 * 
 * 		Password.getSecurityPolicy.setStrict(false)
 *
 * The Password contains a creationDate which, depending on SecurityPolicy configuration, will
 * cause a password to expire after a period of time. Password.isExpired() will return true in 
 * this case. Password contains a history array of previous passwords, this is to prevent reuse
 * of passwords, if configured. The history count is defined in SecurityPolicy.
 */
public class Password {
	private Date creationDate;
	private Password.CharArray charArray;
	private String[] history;
	private String secret;
	private boolean expired;
	private boolean isNew;
	
	/* This constructor is called when creating a Password for verification purposes. */
	public Password(char[] plainText) { this(plainText, false); }
	/*
	 * This constructor is called when creating new passwords. The history array size is the 
	 * predefined histoyCount minus the current password which also counts as a past password
	 * once set and therefore history[] size is created -1. A call to change() is used to set
	 * the password.
	 */
	public Password(char[] plainText, boolean isNew) {
		// If historyCount = 0 we don't want to attempt to create a negative array which would
		// cause a crash. In this case we create a dummy array of size 0 and this is to ensure
		// that calls to getHistoty will not crash with NullPointerException.
		if (this.getSecurityPolicy().getHistoryCount() > 0)
			this.setHistory(new String[this.getSecurityPolicy().getHistoryCount() - 1]); // all values = null
		else
			this.setHistory(new String[0]);

		this.change(plainText, isNew); // use change method to set the password
	}
	/*
	 * This constructor is called when creating passwords from persistence. Once the persisted
	 * values are set it does an expiration check. The SecurityPolicy will determine if this 
	 * password has expired based on the creation date or if the SecurityPolicy has been updated
	 * and requires all passwords to be recreated under the new rules.
	 */
	public Password(String secret, String[] history, Date creationDate) {
		this.setSecret(secret);
		this.setHistory(history);
		this.setCreationDate(creationDate);
		this.getSecurityPolicy().expirationCheck(this);
	}
	
	/*
	 * The change method will attempt to change the password to the char[] passed in. Internally
	 * Password uses a CharArray which is a CharSequence implementation required by SecurityPolicy.
	 * A check is made to see if the history count has been modified which could happen with a 
	 * SecurityPolicy update.It then attempts to create a secret password and if it succeeds it
	 * puts the previous secret into the history array.
	 *
	 * SecurityPolicy will throw a SecurityException if it encounters any conflicts. If the secret
	 * password is successfully created the CharArray is cleared, the password creation date is
	 * set, and isNew is set to false as validation is complete and the encrypted input is now the 
	 * currently set secret password.
	 *
	 * An existing password only has access to change(char[]) but a newly created password calls
	 * change(char[], isNew) because newly created passwords can be for verification whereby 
	 * isNew=false or for creation isNew=true. An existing password change is always a new password
	 * and therefore isNew=true.
	 */
	public void change(char[] plainText) throws SecurityException {
		this.change(plainText, true);
	}
	private void change(char[] plainText, boolean isNew) throws SecurityException {
		this.setIsNew(isNew); // this flags whether or not to do security checking
		this.setCharArray(new Password.CharArray(plainText));
		
		// if the history count has been changed, modify the array length. if history count
		// has been disabled then set history to a new dummy array.
		// Note: -1 is applied to historyCount to reflect the history size offset
		if (this.getSecurityPolicy().getHistoryCount() > 0) {
			if (this.getHistory().length != this.getSecurityPolicy().getHistoryCount() - 1)
				this.setHistory(Arrays.copyOf(this.getHistory(), this.getSecurityPolicy().getHistoryCount() - 1));
		}
		else {
			this.setHistory(new String[0]);
		}
		
		// need to keep a copy of the current secret password to put into history
		String previousSecret = this.getSecret();
		
		this.getSecurityPolicy().encrypt(this); // will throw SecurityException on conflicts
		
		// put previous secret into history
		if (history.length != 0) {
			for (int i = history.length - 2; i > -1; i--) {
				history[i+1] = history[i];
			}
			history[0] = previousSecret;
		}
		
		// clean up
		this.getCharArray().clear();
		this.setCreationDate(new Date());
		this.setIsNew(false);
	}
		
	/* Password equality is determined by comparing the secret passwords. */
	public boolean equals(Password password) { return equals(password.getSecret()); }
	public boolean equals(String secret) {
		if (this.getSecret().equals(secret))
			return true;
		else return false;
	}
	
	/* default access gives SecurityPolicy access to the CharArray. */
	CharArray getCharArray() { return this.charArray; }
	
	public Date getCreationDate() { return this.creationDate; }
	
	/* This method will be called by a persistor and should not return any null values. */
	public String[] getHistory() {
		for (int i = 0; i < this.history.length; i++) {
			if (this.history[i] == null)
				this.history[i] = "";
		}
		return this.history; 
	}
	
	public String getSecret() { return this.secret; }
	
	/* A convenience method for access to the SecurityPolicy. */
	public static SecurityPolicy getSecurityPolicy() { return SecurityPolicy.getInstance(); }
	
	/* 
	 * Once a password has been restored from persistance this method should be called to
	 * ensure it is complient with the Securitypolicy rules and is not out of date.
	 */
	public boolean isExpired() { return this.expired; }
	
	/* This will return true if the password is new, and false if it is a temp password */
	boolean isNew() { return this.isNew; }
	
	private void setCharArray(Password.CharArray charArray) { this.charArray = charArray; }
	
	private void setCreationDate(Date creationDate) { this.creationDate = creationDate; }
	
	/* This method is used by SecurityPolicy and should not be directly used. */
	void setExpired(boolean expired) { this.expired = expired; }
	
	private void setHistory(String[] history) { this.history = history; }
	
	void setIsNew(boolean isNew) { this.isNew = isNew; }
	
	/* This method is used by SecurityPolicy to set the newly created secret password. */
	void setSecret(String secret) { this.secret = secret; }
	
	public String toString() { return this.getSecret(); }
	
	/*
	 * CharArray is a CharSequence implementation which is required by SecurityPolicy for
	 * rule checking. It has an added clear() method to clear out any contents and a 
	 * getBytes() method which converts the char[] into a byte[] without the use of String.
	 * String objects should not be used for sensitive data storage due to their immutable
	 * nature. getBytes() is required to apply the encryption algorithm.
	 */
	class CharArray implements CharSequence {
		private byte[] bytes;
		private char[] ary;
		
		/* ary is the character array represented by this CharArray. */
		public CharArray(char[] ary) { this.ary = ary; }
		
		/* Required by CharSequence. */
		public char charAt(int index) { return ary[index]; }
		
		/* Clears out the contents of ary[] and bytes[]. */
		public void clear() { 
			Arrays.fill(ary, '\u0000');
			if (bytes != null) // it is possible getBytes never gets called
				Arrays.fill(bytes, (byte)0);
		}
		
		/* Convert the character array into a byte array. */
		public byte[] getBytes() {
			CharBuffer cb = CharBuffer.wrap(ary);
			ByteBuffer bb = Charset.forName("UTF-8").encode(cb);
			bytes = Arrays.copyOfRange(bb.array(), bb.position(), bb.limit());
			
			Arrays.fill(cb.array(), '\u0000');
			Arrays.fill(bb.array(), (byte)0);
			
			return bytes;
		}
		
		/* Required by CharSecuence. */
		public int length() { return ary.length; }
		
		/* Required by CharSecuence. */
		public CharSequence subSequence(int start, int end) {
			char[] subAry = new char[end - start];
			
			for (int i = 0; i < subAry.length; i++)
				subAry[i] = ary[i + start];
			
			return new CharArray(subAry);
		}
		
		/*                                                
		 * The only place this is called is if SecurityPolicy is disabled and the 
		 * secret password is set to the plain text input.
		 */
		public String toString() { return new String(ary); }
	}
}