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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.ejbca.util.Base64;

/**
 * @version $Id: KeyStore.java,v 1.4 2008-01-07 13:07:27 anatom Exp $
 */
public class KeyStore extends TokenCertificateResponseWS {
	
	private byte[] keystoreData = null;
	
	public KeyStore(){
		
	}

	public KeyStore(java.security.KeyStore keystore, String password) throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException{
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		keystore.store(baos,password.toCharArray());
		keystoreData = Base64.encode(baos.toByteArray());
	}


	
	/**
	 * @return Returns the keystoreData, in Base64 encoded format.
	 */
	public byte[] getKeystoreData() {
		return keystoreData;
	}

	/**
	 * @param keystoreData The keystoreData to set, in Base64 encoded format.
	 */
	public void setKeystoreData(byte[] keystoreData) {
		this.keystoreData = keystoreData;
	}


}
