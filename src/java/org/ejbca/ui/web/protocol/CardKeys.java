package org.ejbca.ui.web.protocol;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author lars
 *
 */
public interface CardKeys {

	/**
	 * @param publicKey
	 * @return
	 */
	PrivateKey getPrivateKey(PublicKey publicKey) throws Exception;
}
