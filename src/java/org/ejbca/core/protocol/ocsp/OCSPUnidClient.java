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

import java.security.KeyStore;
import java.security.cert.X509Certificate;

/** A simple OCSP lookup client used to query the OCSPUnidExtension
 * 
 * @author tomas
 * @version $Id: OCSPUnidClient.java,v 1.2 2006-02-08 07:31:47 anatom Exp $
 *
 */
public class OCSPUnidClient {

	/** 
	 * 
	 * @param ks KeyStore client keystore used to authenticate TLS client authentication
	 */
	public OCSPUnidClient(KeyStore ks) {
		// TODO:
	}
	
	/**
	 * 
	 * @param cert X509Certificate to query, the DN should contain serialNumber which is Unid
	 * @param cacert X509Certificate to query, the DN should contain serialNumber which is Unid
	 * @param ocspurl String url to the OCSP server, e.g. http://127.0.0.1:8080/ejbca/publicweb/status/ocsp 
	 * @param getfnr if we should ask for a Unid-Fnr mapping or only query the OCSP server
	 * @return OCSPUnidResponse
	 */
	public OCSPUnidResponse lookup(X509Certificate cert, X509Certificate cacert, String ocspurl, boolean getfnr) {	
		// TODO:
		return null;
	}
}
