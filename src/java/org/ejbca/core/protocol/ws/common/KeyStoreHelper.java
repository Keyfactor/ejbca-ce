package org.ejbca.core.protocol.ws.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import org.ejbca.util.Base64;


/**
 * Class used to generate a java.security.KeyStore from a 
 * org.ejbca.core.protocol.ws.common.KeyStore
 * 
 * @author Philip Vendil
 *
 * $id$
 */

public class KeyStoreHelper {

	/**
	 * Retrieves the keystore from the encoded data.
	 * @param type "PKCS12" or "JKS"
	 * @param password to lock the keystore
	 * @return the loaded and unlocked keystore.
	 * @throws CertificateException
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws NoSuchProviderException 
	 * @throws KeyStoreException 
	 */
	public static java.security.KeyStore getKeyStore(byte[] keystoreData, String type, String password) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, NoSuchProviderException{
		java.security.KeyStore ks = java.security.KeyStore.getInstance(type, "BC");
		ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decode(keystoreData));
		ks.load(bais, password.toCharArray());
        return ks; 
	}
}
