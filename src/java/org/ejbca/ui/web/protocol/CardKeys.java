package org.ejbca.ui.web.protocol;

import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author lars
 *
 */
public interface CardKeys {

	/**
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	PrivateKey getPrivateKey(RSAPublicKey publicKey) throws Exception;
    /**
     * @param authCode
     * @throws InterruptedException
     */
    void autenticate( String authCode) throws InterruptedException;
}
