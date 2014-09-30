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
package org.ejbca.core.protocol.certificatestore;

import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.ca.internal.CaCertificateCache;
import org.cesecore.certificates.certificate.HashID;

/** class used from TestCertificateCache
 * 
 * @version $Id$
 */
public class CacheTester implements Runnable { // NOPMD, this is not a JEE app, only a test
	private CaCertificateCache cache = null;
	private String dn;
	public CacheTester(CaCertificateCache cache, String lookfor) {
		this.cache = cache;
		this.dn = lookfor;
	}
	public void run() {
		for (int i=0; i<1000;i++) {
			X509Certificate cert = cache.findLatestBySubjectDN(HashID.getFromDNString(dn));
			// The cache tests will not return any CV Certificates because this OCSP cache 
			// only handles X.509 Certificates.
			if (!StringUtils.contains(dn, "CVCTest")) {
				cert.getSubjectDN(); // just to see that we did receive a cert, will throw NPE if no cert was returned				
			}
		}    			
	}
}
	
