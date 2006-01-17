/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.ca.catoken;

import java.io.Serializable;

/**
 * Holds properties of a HardCAToken.
 *
 * @version $Id: HardCATokenInfo.java,v 1.1 2006-01-17 20:31:51 anatom Exp $
 */
public class HardCATokenInfo extends CATokenInfo implements Serializable {    
    
	String properties;
	String classPath;
	String authenticationCode;
	int cATokenStatus;
	
    public HardCATokenInfo(){}
    
    public String getClassPath(){
    	return classPath;
    }
    
    public void setClassPath(String classpath){
    	this.classPath = classpath;
    }
    
    public String getProperties(){
    	return properties;
    }
    
    public void setProperties(String properties){
    	this.properties = properties;
    }
        
	/**
	 * @return Returns the authenticationcode.
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
	
	/**
	 * 
	 * @param catokenstatus is one of IHardCAToken.STATUS_.. constants
	 */
	public void setCATokenStatus(int catokenstatus){
	  this.cATokenStatus = catokenstatus;	
	}
	
	/**
	 * 
	 * @return catokenstatus, one of IHardCAToken.STATUS_.. constants
	 */
	public int getCATokenStatus(){
	  return cATokenStatus;	
	}
}
