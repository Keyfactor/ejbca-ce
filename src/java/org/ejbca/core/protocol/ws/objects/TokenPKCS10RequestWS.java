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

import org.bouncycastle.jce.PKCS10CertificationRequest;

/**
 * Class is a WS representation of a PKCS10 request.
 * 
 * 
 * @author Philip Vendil 2007 feb 8
 *
 * @version $Id: TokenPKCS10RequestWS.java,v 1.2 2007-03-07 10:08:55 herrvendil Exp $
 */

public class TokenPKCS10RequestWS extends TokenCertificateRequestWS{

	private byte[] pkcs10Data = null;

	public TokenPKCS10RequestWS(){}
	
	/**
	 * Constructor creating a WS compliant value object from a PKCS10
	 * @param pkcs10 
	 */
	public TokenPKCS10RequestWS(PKCS10CertificationRequest pkcs10){
		this.pkcs10Data = pkcs10.getEncoded();
	}
	
	/**
	 * 
	 * @return the byte representation of the PKCS10 data
	 */
	public byte[] getPkcs10Data() {
		return pkcs10Data;
	}

	/**
	 * 
	 * @param pkcs10Data the byte representation of the PKCS10 data
	 */
	public void setPkcs10Data(byte[] pkcs10Data) {
		this.pkcs10Data = pkcs10Data;
	}
	
	
}
