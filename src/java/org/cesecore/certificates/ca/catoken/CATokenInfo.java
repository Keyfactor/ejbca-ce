/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.ca.catoken;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.StringWriter;
import java.util.Properties;

import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.StringTools;

/**
 * Holds non sensitive information about a CryptoToken.
 *
 * Based on EJBCA version: CATokenInfo.java 8828 2010-03-29 08:10:51Z anatom
 * 
 * @version $Id: CATokenInfo.java 403 2011-03-02 10:43:47Z tomas $
 */
public class CATokenInfo implements Serializable {

    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    private static final long serialVersionUID = -8484441028763008079L;

	/** Default algorithm i SHA1WithRSA, can be set to any of the supported constants */
    private String signaturealgoritm = AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
	/** Default algorithm i SHA1WithRSA, can be set to any of the supported constants */
    private String encryptionalgoritm = AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
	/** indicates if the token is available for use, i.e. if the authenticationCode has been entered and the hardware is functioning */
	private int tokenStatus = CryptoToken.STATUS_OFFLINE;
	/** Properties for the Crypto token, for example PIN code, this is a string version if Properties that can be loaded in to a Properties class */
	private String properties;
	/** Classpath of the java class implementing the particular type of CA Token */
	private String classPath;
    /** Format according to which the key sequence needs to be incremented */
    private int sequenceFormat = StringTools.KEY_SEQUENCE_FORMAT_NUMERIC;
	/** Key sequence to be updated when keys are re-generated */
    private String sequence = CAToken.DEFAULT_KEYSEQUENCE; // Default value first time token is created
    /** Authentication code to activate a CA Token, can be PIN for a smartcard/HSM or password for a PKCS12 */
	private String authenticationCode;

    public CATokenInfo() {}
    
    /**
     * Method to retrieve which algorithm that should be used for signing certificate.
     */
    public String getSignatureAlgorithm(){ return signaturealgoritm; }
	/** Default algorithm i SHA1WithRSA, can be set to any of the supported constants 
	 * @param signaturealgorithm Any of the supported algorithms AlgorithmConstants.SIGALG_XX 
	 */
    public void setSignatureAlgorithm(String signaturealgoritm){ this.signaturealgoritm=signaturealgoritm;}
    /**
     * Method to retrieve which algoritm that should be used for encryption certificate.
     */
    public String getEncryptionAlgorithm(){ return encryptionalgoritm; }
	/** Default algorithm i SHA1WithRSA, can be set to any of the supported constants 
	 * @param encryptionalgoritm Any of the supported algorithms AlgorithmConstants.SIGALG_XX 
	 */
    public void setEncryptionAlgorithm(String encryptionalgoritm){ this.encryptionalgoritm=encryptionalgoritm;}
	
	/**
	 * 
	 * @param catokenstatus is one of CryptoToken.STATUS_.. constants
	 */
	public void setTokenStatus(int tokenstatus){
	  this.tokenStatus = tokenstatus;	
	}
	
	/**
	 * 
	 * @return tokenstatus, one of CryptoToken.STATUS_.. constants
	 */
	public int getTokenStatus(){
	  return tokenStatus;	
	}

    public String getClassPath(){
    	return classPath;
    }
    
    public void setClassPath(String classpath){
    	this.classPath = classpath;
    }
    
    public String getPropertiesString(){
    	return properties;
    }

    public Properties getProperties() {
    	Properties prop = new Properties();
    	String str = getPropertiesString();
    	if (str != null) {
    		try {
				prop.load(new ByteArrayInputStream(str.getBytes()));
			} catch (IOException e) {
				// do nothing
			}					
    	}
    	return prop;
    }

    public void setProperties(Properties properties){
    	StringWriter sw = new StringWriter();
    	try {
    		properties.store(sw, null);
    	} catch (IOException e) {
    		// do nothing
    	}					
    	setProperties(sw.toString());
    }

    
    public void setProperties(String properties){
    	this.properties = properties;
    }

    /**
     * Method to retrieve the sequence of keys
     */
    public int getKeySequenceFormat(){ return sequenceFormat; }
    /** Sequence of the signature keys 
     * @param sequence 
     */
    public void setKeySequenceFormat(int sequenceFormat){ this.sequenceFormat=sequenceFormat;}
    /**
     * Method to retrieve the sequence of keys
     */
    public String getKeySequence(){ return sequence; }
	/** Sequence of the signature keys 
	 * @param sequence 
	 */
    public void setKeySequence(String sequence){ this.sequence=sequence;}

	/**
	 * @return Returns the authentication code.
	 */
	public String getAuthenticationCode() {
		return authenticationCode;
	}
	/**
	 * @param authenticationcode The authenticationcode to set.
	 */
	public void setAuthenticationCode(String authenticationcode) {
		this.authenticationCode = authenticationcode;
	}

}
