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

import java.security.cert.CertificateEncodingException;

import org.cesecore.util.Base64;

/**
 * Holds certificate WS elements
 * 
 * @version $Id$
 */
public class Certificate extends TokenCertificateResponseWS {
	
	private byte[] certificateData = null;
	
	/**
	 * WS Constructor
	 */
	public Certificate(){
		
	}

	public Certificate(java.security.cert.Certificate cert) throws CertificateEncodingException{
		certificateData = Base64.encode(cert.getEncoded());
	}
	
	public Certificate(byte[] certData) {
		certificateData = Base64.encode(certData);
	}

	/**
	 * Returns the certificateData in binary format
	 * @return the certificateData in binary format
	 */
	public byte[] getRawCertificateData() {
		return Base64.decode(certificateData);
	}

	/**
	 * Returns the certificateData in Base64 encoded format
	 * @return the certificateData in Base64 encoded format
	 */
	public byte[] getCertificateData() {
		return certificateData;
	}

	/**
	 * Sets certificateData in Base64 encoded format
	 * @param certificateData The certificateData to set, in Base64 encoded format.
	 */
	public void setCertificateData(byte[] certificateData) {
		this.certificateData = certificateData;
	}


}
