package org.ejbca.core.protocol.ws;

import java.io.Serializable;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.UserDataConstants;

/**
 * Class used to represent userdata in the WebService API.
 * Is used instead of UserDataVO because of profilenames is used instead of id's.
 * 
 * @author Philip Vendil
 * $id$
 */

public class UserDataVOWS implements Serializable{
	
	public static final java.lang.String TOKEN_TYPE_USERGENERATED = "USERGENERATED"; 
	public static final java.lang.String TOKEN_TYPE_JKS           = "JKS";
	public static final java.lang.String TOKEN_TYPE_PEM           = "PEM";
	public static final java.lang.String TOKEN_TYPE_P12           = "P12";
	
    public static final int STATUS_NEW = UserDataConstants.STATUS_NEW;        // New user
    public static final int STATUS_FAILED = UserDataConstants.STATUS_FAILED;     // Generation of user certificate failed
    public static final int STATUS_INITIALIZED = UserDataConstants.STATUS_INITIALIZED;// User has been initialized
    public static final int STATUS_INPROCESS = UserDataConstants.STATUS_INPROCESS;  // Generation of user certificate in process
    public static final int STATUS_GENERATED = UserDataConstants.STATUS_GENERATED;  // A certificate has been generated for the user
    public static final int STATUS_REVOKED = UserDataConstants.STATUS_REVOKED;  // The user has been revoked and should not have any more certificates issued
    public static final int STATUS_HISTORICAL = UserDataConstants.STATUS_HISTORICAL; // The user is old and archived
    public static final int STATUS_KEYRECOVERY  = UserDataConstants.STATUS_KEYRECOVERY; // The user is should use key recovery functions in next certificate generation.
	
    private java.lang.String username = null;
    private java.lang.String password = null;
    private boolean clearPwd = false;
    private java.lang.String subjectDN = null;
    private java.lang.String caName = null;
    private java.lang.String subjectAltName = null;
    private java.lang.String email = null;
    private int status = 0;
    private java.lang.String tokenType = null;
    private boolean sendNotification = false;
    private boolean keyRecoverable = false;
    private java.lang.String endEntityProfileName = null;
    private java.lang.String certificateProfileName = null;
    private java.lang.String hardTokenIssuerName = null;	


    /**
     * Emtpy constructor used by internally by web services
     */
    public UserDataVOWS(){}
    
	/**
	 * Constructor used when creating a new UserDataVOWS.
	 * 
	 * @param username the unique username if the user, used internally in EJBCA
	 * @param password, password used to lock the keystore
	 * @param subjectDN of 
	 * @param caName the name of the CA used in the EJBCA web gui.
	 * @param subjectAltName
	 * @param email 
	 * @param status one of the STATUS_ constants
	 * @param tokenType type of token, one of TOKEN_TYPE constants for soft tokens, for hard ones  use hardtokenprofilename
	 * @param endEntityProfileName
	 * @param certificateProfileName
	 * @param hardTokenIssuerName if no hardTokenIssuer should be used then use null.
	 */
	public UserDataVOWS(java.lang.String username, java.lang.String password, boolean clearPwd, java.lang.String subjectDN, java.lang.String caName, java.lang.String subjectAltName, java.lang.String email, int status, java.lang.String tokenType, java.lang.String endEntityProfileName, java.lang.String certificateProfileName, java.lang.String hardTokenIssuerName) {
		super();
		this.username = username;
		this.password = password;
		this.clearPwd = clearPwd;
		this.subjectDN = subjectDN;
		this.caName = caName;
		this.subjectAltName = subjectAltName;
		this.email = email;
		this.status = status;
		this.tokenType = tokenType;
		this.endEntityProfileName = endEntityProfileName;
		this.certificateProfileName = certificateProfileName;
		this.hardTokenIssuerName = hardTokenIssuerName;
	}

    
    /**
     * 
     * @return true if the user is keyrecoverable
     */
    public boolean getKeyRecoverable(){
    	return this.keyRecoverable;
    }
    
    /**
     * indicates if the users keys should be keyrecoverable
     * @param keyrecoverable
     */
    public void setKeyRecoverable(boolean keyrecoverable){
      this.keyRecoverable = keyrecoverable;
    }
    
    /**
     * If true notifications will be sent to the user
     */
	public boolean getSendNotification(){
    	return sendNotification;
    }
    
	/**
	 * set to true if notifications should be sent to the user.
	 */
    public void setSendNotification(boolean sendnotification){
    	this.sendNotification = sendnotification;
    }
    
    /**
	 * @return Returns the cAName.
	 */
	public java.lang.String getCaName() {
		return caName;
	}


	/**
	 * @return Returns the certificateProfileName.
	 */
	public java.lang.String getCertificateProfileName() {
		return certificateProfileName;
	}


	/**
	 * @return Returns the email.
	 */
	public java.lang.String getEmail() {
		return email;
	}


	/**
	 * @return Returns the endEntityProfileName.
	 */
	public java.lang.String getEndEntityProfileName() {
		return endEntityProfileName;
	}


	/**
	 * @return Returns the hardTokenIssuerName.
	 */
	public java.lang.String getHardTokenIssuerName() {
		return hardTokenIssuerName;
	}


	/**
	 * Observe when sending userdata to clients outside EJBCA will the password
	 * always be null.
	 * 
	 * @return Returns the password.
	 */
	public java.lang.String getPassword() {
		return password;
	}

	/**
	 * Observe sending usedata to clients outside EJBCA will always return false
	 * @return Returns the clearpwd.
	 */
	public boolean getClearPwd() {
		return clearPwd;
	}

	/**
	 * @return Returns the status.
	 */
	public int getStatus() {
		return status;
	}


	/**
	 * @return Returns the subjecDN.
	 */
	public java.lang.String getSubjectDN() {
		return subjectDN;
	}


	/**
	 * @return Returns the subjectAltName.
	 */
	public java.lang.String getSubjectAltName() {
		return subjectAltName;
	}


	/**
	 * @return Returns the tokenType. One of TOKEN_TYPE constants for soft tokens, for hard ones  use hardtokenprofilename
	 */
	public java.lang.String getTokenType() {
		return tokenType;
	}


	/**
	 * @return Returns the type.
	 */
	public int getType() {
		int type = 1;
		
    	if(sendNotification)
    		type = type | SecConst.USER_SENDNOTIFICATION;
    	else
    		type = type & (~SecConst.USER_SENDNOTIFICATION);
    	
    	if(keyRecoverable)
    		type = type | SecConst.USER_KEYRECOVERABLE;
    	else
    		type = type & (~SecConst.USER_KEYRECOVERABLE);
    			
		return type;
	}


	/**
	 * @return Returns the username.
	 */
	public java.lang.String getUsername() {
		return username;
	}

	/**
	 * @param name The cAName to set.
	 */
	public void setCaName(java.lang.String name) {
		caName = name;
	}

	/**
	 * @param certificateProfileName The certificateProfileName to set.
	 */
	public void setCertificateProfileName(java.lang.String certificateProfileName) {
		this.certificateProfileName = certificateProfileName;
	}

	/**
	 * @param clearpwd The clearpwd to set.
	 */
	public void setClearPwd(boolean clearPwd) {
		this.clearPwd = clearPwd;
	}

	/**
	 * @param email The email to set.
	 */
	public void setEmail(java.lang.String email) {
		this.email = email;
	}

	/**
	 * @param endEntityProfileName The endEntityProfileName to set.
	 */
	public void setEndEntityProfileName(java.lang.String endEntityProfileName) {
		this.endEntityProfileName = endEntityProfileName;
	}

	/**
	 * @param hardTokenIssuerName The hardTokenIssuerName to set.
	 */
	public void setHardTokenIssuerName(java.lang.String hardTokenIssuerName) {
		this.hardTokenIssuerName = hardTokenIssuerName;
	}

	/**
	 * @param password The password to set.
	 */
	public void setPassword(java.lang.String password) {
		this.password = password;
	}

	/**
	 * @param status The status to set.
	 */
	public void setStatus(int status) {
		this.status = status;
	}

	/**
	 * @param subjectAltName The subjectAltName to set.
	 */
	public void setSubjectAltName(java.lang.String subjectAltName) {
		this.subjectAltName = subjectAltName;
	}

	/**
	 * @param subjectDN The subjectDN to set.
	 */
	public void setSubjectDN(java.lang.String subjectDN) {
		this.subjectDN = subjectDN;
	}

	/**
	 * @param tokenType The tokenType to set.
	 */
	public void setTokenType(java.lang.String tokenType) {
		this.tokenType = tokenType;
	}



	/**
	 * @param username The username to set.
	 */
	public void setUsername(java.lang.String username) {
		this.username = username;
	}
	

	
	

		

}
