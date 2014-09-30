/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
/*
 * AdminInformation.java
 *
 * Created on den 19 juli 2002, 11:53
 */

package org.ejbca.core.model.authorization;

import java.io.Serializable;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Random;

/**
 * A class used to send user information to the authorization tree. It can contain types of information, a X509Certificate or a
 * special user type when certificates cannot be retrieved. Special usertype constants is specified in AdminEntity class.
 *
 * @version $Id$
 */
public class AdminInformation implements Serializable {

	private static final long serialVersionUID = 1L;
	
	// Special in JVM random token to authenticate specialuser. 
	// The token will work _if_ we are running within the same jvm as the service we call (i.e. EJBCA/JBoss server)
	protected static final byte[] randomToken = createRandomToken();
	
	// Public Methods
     /** Creates a new instance of AdminInformation */
    public AdminInformation(Certificate certificate, byte[] authToken) {
      this.certificate=certificate;
      this.specialuser=0;      
      this.localAuthToken = authToken;
    }
    
    public AdminInformation(int specialuser, byte[] authToken) {
      this.specialuser=specialuser;
      this.localAuthToken = authToken;
    }
    
    private AdminInformation(byte[] authToken) { 
  	  this.specialuser = 0;      
  	  this.localAuthToken = authToken;
  	}

    public static AdminInformation getAdminInformationByRoleId(int roleId) {
    	AdminInformation adminInformation = new AdminInformation(getRandomToken()); 
    	adminInformation.adminGroupId = roleId;
    	return adminInformation;
    }
    
	public static final byte[] createRandomToken() {
    	byte[] token = new byte[32];
        Random randomSource;
        randomSource = new SecureRandom();
        randomSource.nextBytes(token);
    	return token;
	}

    public boolean isSpecialUser() {
      return this.specialuser!=0;
    }
    
    public boolean isGroupUser() {
      return this.adminGroupId != null;	
    }

    public Certificate getX509Certificate() {
      return this.certificate;
    }

    public int getSpecialUser() {
      return this.specialuser;
    }
    
    public int getGroupId(){
      return this.adminGroupId;	
    }

	public byte[] getLocalAuthToken() {
		return localAuthToken;
	}

	public static final byte[] getRandomToken() {
		return randomToken;
	}

    // Private fields
    private Certificate certificate;
    private int specialuser = 0;
    private Integer adminGroupId = null;
    
    /** transient as authToken should _not_ be serialized. **/
    private transient byte[] localAuthToken;
    
}
