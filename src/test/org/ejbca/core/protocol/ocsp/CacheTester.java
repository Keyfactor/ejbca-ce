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

import java.security.cert.X509Certificate;

/** class used from TestCertificateCache
 * 
 * @author tomas
 * @version $Id: TestCertificateCache.java 6551 2008-11-05 17:08:58Z anatom $
 */
public class CacheTester implements Runnable {
	private CertificateCache cache = null;
	private String dn;
	public CacheTester(CertificateCache cache, String lookfor) {
		this.cache = cache;
		this.dn = lookfor;
	}
	public void run() {
		for (int i=0; i<1000;i++) {
			X509Certificate cert = cache.findLatestBySubjectDN(dn);
		}    			
	}
}
	
