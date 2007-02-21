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

package org.ejbca.core.protocol.ws.objects;

/**
 * Class is a WS representation of a Token KeyStore request
 * 
 * 
 * @author Philip Vendil 2007 feb 8
 *
 * @version $Id: TokenKeyStoreRequestWS.java,v 1.1 2007-02-21 09:11:12 herrvendil Exp $
 */

public class TokenKeyStoreRequestWS implements ITokenCertificateRequestWS {
    
	private String tokenType = "PKCS12";
	private String keyspec = "1024";
	private String keyalg = "RSA";
	
	public TokenKeyStoreRequestWS(){}
	
	
	
	/**
	 * @param tokenType either PKCS12 or JKS
	 * @param keyspec (ex 1024 for RSA keys)
	 * @param keyalg (ex RSA)
	 */
	public TokenKeyStoreRequestWS(String tokenType, String keyspec, String keyalg) {
		super();
		this.tokenType = tokenType;
		this.keyspec = keyspec;
		this.keyalg = keyalg;
	}



	/**
	 * @return the keyalg
	 */
	public String getKeyalg() {
		return keyalg;
	}
	/**
	 * @param keyalg the keyalg to set
	 */
	public void setKeyalg(String keyalg) {
		this.keyalg = keyalg;
	}
	/**
	 * @return the keyspec (ex 1024 for RSA keys)
	 */
	public String getKeyspec() {
		return keyspec;
	}
	
	/**
	 * @param keyspec the keyspec  (ex 1024 for RSA keys) to set
	 */
	public void setKeyspec(String keyspec) {
		this.keyspec = keyspec;
	}
	/**
	 * @return the tokenType either PKCS12 or JKS
	 */
	public String getTokenType() {
		return tokenType;
	}
	/**
	 * @param tokenType the tokenType to set either PKCS12 or JKS
	 */
	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}
	
	
}
