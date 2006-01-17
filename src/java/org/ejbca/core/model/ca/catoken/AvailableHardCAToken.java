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

/**
 * Value class containing information about an available hard catoken registered to the HardCATokenManager.
 * 
 * @author herrvendil
 * @version $Id: AvailableHardCAToken.java,v 1.1 2006-01-17 20:31:51 anatom Exp $
 */
public class AvailableHardCAToken {
	
	private String classpath;
	private String name;
	private boolean translateable;
	private boolean use;
	
	public AvailableHardCAToken(String classpath, String name, boolean translateable, boolean use){
		this.classpath = classpath;
		this.name = name;
		this.translateable = translateable;
		this.use = use;
	}
	
	
	/**
	 *  Method returning the classpath used to create the plugin. Must implement the HardCAToken interface.
	 * 
	 */
	public String getClassPath(){
		return this.classpath;
	}
	
	/**
	 *  Method returning the general name of the plug-in used in the adminweb-gui. If translateable flag is 
	 *  set then must the resource be in the language files.
	 * 
	 */	
	
	public String getName(){
		return this.name;		
	}

	/**
	 *  Indicates if the name should be translated in the adminweb-gui. 
	 * 
	 */	
	public boolean isTranslateable(){
		return this.translateable;
	}

	/**
	 *  Indicates if the plug should be used in the system or if it's a dummy or test class.
	 * 
	 */		
	public boolean isUsed(){
		return this.use;
	}

}
