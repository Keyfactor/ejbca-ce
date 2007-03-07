package org.ejbca.core.protocol.ws.common;

import org.bouncycastle.jce.PKCS10CertificationRequest;


/**
 * Class used to generate a PKCS10CertificationRequest from a 
 * org.ejbca.core.protocol.ws.common.ToeknPKCS10Request
 * 
 * @author Philip Vendil
 *
 * $id$
 */

public class PKCS10Helper {

	/**
	 * Retrieves the pkcs10 from the encoded data.
	 */
	public static PKCS10CertificationRequest getPKCS10(byte[] pkcs10Data) {
		return new PKCS10CertificationRequest(pkcs10Data);
	}
}
