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

import java.io.IOException;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.ejbca.core.model.hardtoken.HardTokenConstants;

/**
 * Base class this is a ITokenCertificateRequest, either
 * a PKCS10 or KeyStore defined by the type field.
 * 
 *
 * @version $Id$
 */
public class TokenCertificateRequestWS {
	

    	
	private String cAName = null;
	private String certificateProfileName = null;
	private String validityIdDays = null;
	private int type = 0;
	private byte[] pkcs10Data = null;
	private String tokenType = HardTokenConstants.TOKENTYPE_PKCS12;
	private String keyspec = "1024";
	private String keyalg = "RSA";
	
	public TokenCertificateRequestWS(String name, String certificateProfileName, String validityIdDays, PKCS10CertificationRequest pkcs10) throws IOException {
		super();
		type = HardTokenConstants.REQUESTTYPE_PKCS10_REQUEST;
		cAName = name;
		this.validityIdDays = validityIdDays;
		this.certificateProfileName = certificateProfileName;
		this.pkcs10Data = pkcs10.getEncoded();
	}
	public TokenCertificateRequestWS(String name, String certificateProfileName, String validityIdDays,String tokenType, String keyspec, String keyalg) {
		super();
		type = HardTokenConstants.REQUESTTYPE_KEYSTORE_REQUEST;
		cAName = name;
		this.validityIdDays = validityIdDays;
		this.certificateProfileName = certificateProfileName;
		this.tokenType = tokenType;
		this.keyspec = keyspec;
		this.keyalg = keyalg;
	}

	/**
	 * WS Constructor
	 */
	public TokenCertificateRequestWS() {
		super();
	}

	public String getCAName() {
		return cAName;
	}

	public void setCAName(String name) {
		cAName = name;
	}

	public String getCertificateProfileName() {
		return certificateProfileName;
	}

	public void setCertificateProfileName(String certificateProfileName) {
		this.certificateProfileName = certificateProfileName;
	}
	public String getKeyalg() {
		return keyalg;
	}
	public void setKeyalg(String keyalg) {
		this.keyalg = keyalg;
	}
	public String getKeyspec() {
		return keyspec;
	}
	public void setKeyspec(String keyspec) {
		this.keyspec = keyspec;
	}
	public byte[] getPkcs10Data() {
		return pkcs10Data;
	}
	public void setPkcs10Data(byte[] pkcs10Data) {
		this.pkcs10Data = pkcs10Data;
	}
	public String getTokenType() {
		return tokenType;
	}
	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}
	public int getType() {
		return type;
	}
	public void setType(int type) {
		this.type = type;
	}
	
	// ANJAKOBS: Name change? AND is returned as relative time with seconds precision '*y *mo *d *h *m *s' now. Communicate it!
	public String getValidityIdDays() {
		return validityIdDays;
	}
	public void setValidityIdDays(String validityIdDays) {
		this.validityIdDays = validityIdDays;
	}

}
