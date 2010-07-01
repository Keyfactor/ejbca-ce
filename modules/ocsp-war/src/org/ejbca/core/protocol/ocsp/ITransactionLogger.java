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

package org.ejbca.core.protocol.ocsp;


/**
 * Transaction logger constants.
 * @author lars
 * @version $Id:
 *
 */
public interface ITransactionLogger extends IOCSPLogger {

	/**
	 * The Common Name (CN) of the client making the request
	 */
	static final String REQ_NAME = "REQ_NAME";
	/**
	 * DN of the issuer of the certificate used to sign the request.
	 */
	static final String SIGN_ISSUER_NAME_DN = "SIGN_ISSUER_NAME_DN";
	/**
	 * Subject Name of the certificate used to sign the request.
	 */
	static final String SIGN_SUBJECT_NAME = "SIGN_SUBJECT_NAME";
	/**
	 * Certificate serial number of the certificate used to sign the request.
	 */
	static final String SIGN_SERIAL_NO = "SIGN_SERIAL_NO";
	/**
	 * The number of certificates to check revocation status for
	 */
	static final String NUM_CERT_ID = "NUM_CERT_ID";
	/**
	 * The subject DN of the issuer of a requested certificate
	 */
	static final String ISSUER_NAME_DN = "ISSUER_NAME_DN";
	/**
	 * Algorithm used by requested certificate to hash issuer key and issuer name
	 */
	static final String DIGEST_ALGOR = "DIGEST_ALGOR";
	/**
	 * The requested certificate revocation status.
	 */
	static final String CERT_STATUS = "CERT_STATUS";
}
