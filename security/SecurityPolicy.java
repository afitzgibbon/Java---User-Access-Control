package org.andy.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.Date;
import java.util.regex.Pattern;
import javax.xml.bind.DatatypeConverter;

/*
 * SecurityPolicy defines the rules for Password creation and once a password is deemed
 * compliant an encryption algorithm is applied to it. It is a Singleton Object and 
 * therefore one instance governs all Password instances to ensures consistancy. By 
 * default, on first creation, it is set to strict mode which applies the following rules:
 * 
 * 		Encryption Algorithm = SHA-256
 *		Password must be at least 8 characters long
 *		Password must contain at least 1 character
 *		Password must contain at least 1 lower case
 *		Password must contain at least 1 upper case
 * 		Password must contain at least 1 digit
 *		Password must contain at least 1 special character
 *		Password cannot contain any white space
 *		Password will expire after 90 days
 *		Passwords cannot be changed to last 3 used (history count = 3)
 *
 * If strict mode is set to false all above rules are turned off but each can be individually 
 * tured back on or modified to create a custom policy. SecurityPolicy has a modification date
 * which is updated if the policy is updated. This will cause all passwords with a creation date 
 * of before this time to become expired. An expired Password will be forced to change its
 * password to the newly updated policy.
 */
public class SecurityPolicy {
	private static final String WARNING = "Warning! Password does not meet security requirements: ";
	private static final int STRICT_MIN_LENGTH = 8;
	private static final int STRICT_HISTORY_COUNT = 3; 
	private static final String STRICT_ALGORITHM = "SHA-256";
	private static final int STRICT_TIME_TO_LIVE = 90;
	
	private Date modificationDate;
	private MessageDigest messageDigest;
	private String algorithm;
	private int historyCount;
	private int minLength;
	private boolean mustContainCharacter;
	private boolean mustContainDigit;
	private boolean mustContainLowerCase;
	private boolean mustContainNoWhitespace;
	private boolean mustContainSpecialCharacter;
	private boolean mustContainUpperCase;
	private int timeToLive;
	
	/* Set up Singleton creation. Use SecurityPolicy.getInstance() to get instance. */
	private static SecurityPolicy instance;
	
	public static SecurityPolicy getInstance() {
		if (instance == null)
			instance = new SecurityPolicy();
			
		return instance;
	}
	
	private SecurityPolicy() {
		this.setModified();
		this.setStrict(true); // by default turn all security rules on
	}
	
	/* 
	 * This encrypts the password using a Message Digest. It returns the digest as
	 * as hexadecimal String.
	 */
	private String computeHash(Password.CharArray charArray) {
		byte[] hash = messageDigest.digest(charArray.getBytes());
		return DatatypeConverter.printHexBinary(hash);
	}
	
	/* 
	 * A Password will call this method to generate and set its secret password
	 * based on its CharArray plain text password.
	 */
	public void encrypt(Password password) throws SecurityException {
		Password.CharArray charArray = password.getCharArray();
		this.validate(charArray); // verify plain text password is complient with rules
		
		String secret;
		if (getEncryptionAlgorithm() != null)
			secret = this.computeHash(charArray);	
		else
			secret = charArray.toString(); // secret == password if no policy is in place
		
		// verify the secret password has not already been used
		String[] history = password.getHistory();
		for (int i = 0; i < history.length; i++) {
			if (secret.equals(history[i]))
				throw new SecurityException(WARNING + "Password exists in history");
		}
		
		// no exceptions have been thrown and therefore password is valid
		password.setSecret(secret);
		password.setExpired(false);
	}
	
	/* 
	 * Password will call this method to verify it has not expired. It will be based
	 * on its creation date v's the TimeToLive rule and also the policy modification 
	 * date. If the policy was updated after the password was created it will force 
	 * the Password to expire and renew itself.
	 */
	public void expirationCheck(Password password) {
		if (this.getTimeToLive() == 0)
			return;
		
		Calendar ttl = Calendar.getInstance();
		ttl.add(Calendar.DATE, (this.getTimeToLive() * -1)); // subtract TTL days from now
		
		if (password.getCreationDate().compareTo(ttl.getTime()) < 0 ||
			password.getCreationDate().compareTo(this.getModificationDate()) < 0)
			password.setExpired(true);
	}
	
	public String getEncryptionAlgorithm() { return algorithm; }
	public int getHistoryCount() { return historyCount; }
	public int getMinimumLength() { return minLength; }
	private Date getModificationDate() { return modificationDate; }
	public int getTimeToLive() { return timeToLive; }
	public boolean mustContainCharacter() { return mustContainCharacter; }
	public boolean mustContainDigit() { return mustContainDigit; }
	public boolean mustContainLowerCase() { return mustContainLowerCase; }
	public boolean mustContainNoWhitespace() { return mustContainNoWhitespace; }
	public boolean mustContainSpecialCharacter() { return mustContainSpecialCharacter; }
	public boolean mustContainUpperCase() { return mustContainUpperCase; }
	
	public void setEncryptionAlgorithm(String algorithm) throws NoSuchAlgorithmException {
		this.algorithm = algorithm;
		if (algorithm == null) 
			return;
		else messageDigest = MessageDigest.getInstance(this.algorithm); // throws ex
	}
	public void setHistoryCount(int historyCount) { this.historyCount = historyCount; }
	public void setMinimumLength(int minLength) { this.minLength = minLength; }
	public void setModified() { this.modificationDate = new Date(); }
	public void setMustContainCharacter(boolean b) { this.mustContainCharacter = b; }
	public void setMustContainDigit(boolean b) { this.mustContainDigit = b; }
	public void setMustContainLowerCase(boolean b) { this.mustContainLowerCase = b; }
	public void setMustContainNoWhitespace(boolean b) { this.mustContainNoWhitespace = b; }
	public void setMustContainSpecialCharacter(boolean b) { this.mustContainSpecialCharacter = b; }
	public void setMustContainUpperCase(boolean b) { this.mustContainUpperCase = b; }
	public void setTimeToLive(int timeToLive) { this.timeToLive = timeToLive; }
	
	/*
	 * This is a convenience method which sets all rules to a default value if set to true and
	 * will essentially disable the SecurityPolicy if set to false.
	 */
	public void setStrict(boolean strict) {
		if (strict) {
			try {
				this.setEncryptionAlgorithm(STRICT_ALGORITHM); // default will not throw ex
			}
			catch (NoSuchAlgorithmException ex) { ex.printStackTrace(); }
			this.setHistoryCount(STRICT_HISTORY_COUNT);
			this.setMinimumLength(STRICT_MIN_LENGTH);
			this.setMustContainCharacter(true);
			this.setMustContainDigit(true);
			this.setMustContainLowerCase(true);
			this.setMustContainNoWhitespace(true);
			this.setMustContainSpecialCharacter(true);
			this.setMustContainUpperCase(true);
			this.setTimeToLive(STRICT_TIME_TO_LIVE);
		}
		else {
			try {
				this.setEncryptionAlgorithm(null); // throws ex but discard it as strict=off is in place
			}
			catch (NoSuchAlgorithmException ex) {}
			this.setHistoryCount(0);
			this.setMinimumLength(0);
			this.setMustContainCharacter(false);
			this.setMustContainDigit(false);
			this.setMustContainLowerCase(false);
			this.setMustContainNoWhitespace(false);
			this.setMustContainSpecialCharacter(false);
			this.setMustContainUpperCase(false);
			this.setTimeToLive(0); // a value of 0 means password will never expire
		}
	}
	
	/*
	 * This method validates the plain text password against the defined rules. It uses
	 * regular expressions to test the rules, and this is why a CharSequence object is 
	 * required. A SecurityException is thrown on the first conflict encountered.
	 */
	private void validate(Password.CharArray charArray) throws SecurityException {
		if (charArray.length() < this.getMinimumLength())
			throw new SecurityException(WARNING + "Not long enough!");
		
		if (mustContainCharacter() && Pattern.matches(".*[a-zA-Z]+.*", charArray) == false)
			throw new SecurityException(WARNING + "No characters used!");
		
		if (mustContainDigit() && Pattern.matches(".*[\\d]+.*", charArray) == false)
			throw new SecurityException(WARNING + "No digit used!");
		
		if (mustContainLowerCase() && Pattern.matches(".*[a-z]+.*", charArray) == false)
			throw new SecurityException(WARNING + "No lower case used!");
		
		if (mustContainNoWhitespace() && Pattern.matches("[^\\s]+", charArray) == false)
			throw new SecurityException(WARNING + "Whitespace character used!");
		
		if (mustContainSpecialCharacter() && Pattern.matches(".*[^a-zA-Z0-9]+.*", charArray) == false)
			throw new SecurityException(WARNING + "No special character used!");
		
		if (mustContainUpperCase() && Pattern.matches(".*[A-Z]+.*", charArray) == false)
			throw new SecurityException(WARNING + "No upper case used!");
	}
}