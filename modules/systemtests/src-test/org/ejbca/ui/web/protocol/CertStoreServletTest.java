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

package org.ejbca.ui.web.protocol;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.mail.MessagingException;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.junit.Test;

/**
 * Testing of CertStoreServlet
 * 
 * @author lars
 * @version $Id$
 *
 */
public class CertStoreServletTest extends CaTestCase {
	private final static Logger log = Logger.getLogger(CertStoreServletTest.class);
	/**
	 * @throws MessagingException 
	 * @throws URISyntaxException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws MalformedURLException 
	 * @throws AuthorizationDeniedException 
	 * @throws CADoesntExistsException 
	 */
	
	@Test
	public void testIt() throws MalformedURLException, CertificateException, IOException, URISyntaxException, MessagingException, CADoesntExistsException, AuthorizationDeniedException {
		final CAInHierarchy ca1 = new CAInHierarchy("root", this);
		final CAInHierarchy ca1_1 = new CAInHierarchy("1 from root", this);
		ca1.subs.add(ca1_1);
		final CAInHierarchy ca2_1 = new CAInHierarchy("2 from root at"+new Date(), this);
		ca1.subs.add(ca2_1);
		final CAInHierarchy ca1_1_1 = new CAInHierarchy("1 from 1 from root", this);
		ca1_1.subs.add(ca1_1_1);
		final CAInHierarchy ca2_1_1 = new CAInHierarchy("2 from 1 from root at "+new Date(), this);
		ca1_1.subs.add(ca2_1_1);
		final CAInHierarchy ca3_1_1 = new CAInHierarchy("3 from 1 from root", this);
		ca1_1.subs.add(ca3_1_1);
		
		try {
			final Set<Integer> setOfSubjectKeyIDs = new HashSet<Integer>();
			final X509Certificate rootCert = ca1.createCA(setOfSubjectKeyIDs);
			log.info("The number of CAs created was "+setOfSubjectKeyIDs.size()+".");
			new CertFetchAndVerify().doIt( rootCert, setOfSubjectKeyIDs );
			assertEquals("All created CA certificates not found.", 0, setOfSubjectKeyIDs.size());
		}finally {
			ca1.deleteCA();
		}
	}
}
