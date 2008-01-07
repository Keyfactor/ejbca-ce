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

import org.ejbca.util.Base64;

/**
 * @version $Id: CertificateResponse.java,v 1.2 2008-01-07 13:07:27 anatom Exp $
 */
public class CertificateResponse  {
	
	private String responseType;
	private byte[] data = null;
	
	public CertificateResponse(){
		
	}

	/**
	 * Main constructor.
	 * @param responseType one of the CertificateHelper.RESPONSETYPE_ constants
	 * @param data non-base64 encoded 
	 */
	public CertificateResponse(String responseType, byte[] data) {
		this.data = Base64.encode(data);
		this.responseType = responseType;
	}
	
	/**
	 * @return responseType one of CertificateHelper.RESPONSETYPE_ constants
	 */
	public String getResponseType() {
		return responseType;
	}

	/**
	 * @param responseType one of CertificateHelper.RESPONSETYPE_ constants
	 */
	public void setResponseType(String responseType) {
		this.responseType = responseType;
	}
	
    /**
     * @return the data, Base64 encoded
     * 
     */
	public byte[] getData() {
		return data;
	}

    /**
     * @param data of the type set in responseType, should be Base64 encoded
     * 
     */	
	public void setData(byte[] data) {
		this.data = data;
	}



}
