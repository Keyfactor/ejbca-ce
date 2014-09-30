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

package org.ejbca.core.protocol.ws.client.gen;

import org.ejbca.core.model.hardtoken.HardTokenConstants;

/**
 * base class that this is a certificate response
 * of either a Certificate or KeyStore
 * 
 * 
 * @author Philip Vendil 2007 feb 8
 *
 * @version $Id$
 */
public class TokenCertificateResponseWS {
	


	private int type = 0;
	private Certificate certificate;
	private KeyStore keyStore;
	
	public TokenCertificateResponseWS(Certificate certificate) {
		super();
		this.type = HardTokenConstants.RESPONSETYPE_CERTIFICATE_RESPONSE;
		this.certificate = certificate;
	}

	public TokenCertificateResponseWS(KeyStore keyStore) {
		super();
		this.type = HardTokenConstants.RESPONSETYPE_KEYSTORE_RESPONSE;
		this.keyStore = keyStore;
	}

	/**
	 * WS Constructor
	 */
	public TokenCertificateResponseWS() {
		super();
	}

	public Certificate getCertificate() {
		return certificate;
	}

	public void setCertificate(Certificate certificate) {
		this.certificate = certificate;
	}

	public KeyStore getKeyStore() {
		return keyStore;
	}

	public void setKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
	}

	public int getType() {
		return type;
	}

	public void setType(int type) {
		this.type = type;
	}
	
	
}
