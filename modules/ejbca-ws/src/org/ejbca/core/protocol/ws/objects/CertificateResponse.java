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
package org.ejbca.core.protocol.ws.objects;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.xml.bind.annotation.XmlType;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;

/**
 * Holds certificate WS response data 
 *
 */
@XmlType(name = "certificateResponse", propOrder = {
        "data",
        "responseType"
 })
public class CertificateResponse  {
	
	private String responseType;
	private byte[] data = null;
	
	/**
	 * WS Constructor
	 */
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
     * Returns Base64 encoded data
     * @return the data, Base64 encoded
     * 
     */
	public byte[] getData() {
		return data;
	}

    /**
     * Sets Base64 encode data
     * @param data of the type set in responseType, should be Base64 encoded
     * 
     */	
	public void setData(byte[] data) {
		this.data = data;
	}

	/**
	 * Returns a certificate from the data in the WS response.
	 */
	public X509Certificate getCertificate() throws CertificateException{
        return CertTools.getCertfromByteArray(getRawData(), X509Certificate.class); 
	}
	
	/**
	 * Returns raw PKCS #7 or X509 data instead of the Base64 contained in
	 * the WS response
	 */
	public byte[] getRawData() {
		return Base64.decode(data);
	}
	


}
