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
package org.cesecore.keys.token;

/**
 * Value class containing information about an available crypto token registered to the CryptoTokenCache.
 * 
 * Based on AvailableCryptoToken.java 126 2011-01-21 09:18:01Z tomas from cesecore
 * 
 * @version $Id$
 */
public class AvailableCryptoToken {
	
	private String classpath;
	private String name;
	private boolean translateable;
	private boolean use;
	
	public AvailableCryptoToken(String classpath, String name, boolean translateable, boolean use){
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


	/** Classpath is considered the key for AvailableCryptoToken */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((classpath == null) ? 0 : classpath.hashCode());
		return result;
	}


	/** Classpath is considered the key for AvailableCryptoToken */
	@Override
	public boolean equals(final Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final AvailableCryptoToken other = (AvailableCryptoToken) obj;
		if (classpath == null) {
			if (other.classpath != null) {
				return false;
			}
		} else if (!classpath.equals(other.classpath)) {
			return false;
		}
		return true;
	}


}
