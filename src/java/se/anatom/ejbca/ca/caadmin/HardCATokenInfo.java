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

package se.anatom.ejbca.ca.caadmin;

import java.io.Serializable;

/**
 * Holds properties of a HardCAToken.
 *
 * @version $Id: HardCATokenInfo.java,v 1.1 2004-05-10 04:35:10 herrvendil Exp $
 */
public class HardCATokenInfo extends CATokenInfo implements Serializable {    
    
	String properties;
	String classpath;
	String authenticationcode;
	
    public HardCATokenInfo(){}
    
    public String getClassPath(){
    	return classpath;
    }
    
    public void setClassPath(String classpath){
    	this.classpath = classpath;
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
		return authenticationcode;
	}
	/**
	 * @param authenticationcode The authenticationcode to set.
	 */
	public void setAuthenticationCode(String authenticationcode) {
		this.authenticationcode = authenticationcode;
	}
}
