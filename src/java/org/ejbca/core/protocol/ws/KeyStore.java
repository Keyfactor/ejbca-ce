package org.ejbca.core.protocol.ws;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.ejbca.util.Base64;

public class KeyStore {
	
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
