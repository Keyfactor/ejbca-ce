/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.ca.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.ArrayList;

import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.junit.Test;

/**
 * Based on EJBCA version: CACacheManagerTest.java 11004 2010-12-29 11:57:22Z anatom
 * 
 * @version $Id$
 *
 */
public class CACacheManagerTest {

	@Test
	public void testCACacheManager() {
		X509CAInfo cainfo1 = new X509CAInfo();
		cainfo1.setExtendedCAServiceInfos(new ArrayList<ExtendedCAServiceInfo>());

		CA ca1 = new X509CA(cainfo1);
		ca1.setCAId(12);
		ca1.setName("CA1");

		X509CAInfo cainfo2 = new X509CAInfo();
		cainfo2.setExtendedCAServiceInfos(new ArrayList<ExtendedCAServiceInfo>());
		CA ca2 = new X509CA(cainfo2);
		ca2.setCAId(13);
		ca2.setName("CA2");
		
		// Plain add
		CACacheManager.instance().addCA(12, ca1);
		CACacheManager.instance().addCA(13, ca2);
		CA ca = CACacheManager.instance().getCA(12);
		assertEquals(12, ca.getCAId());
		assertEquals("CA1", ca.getName());
		ca = CACacheManager.instance().getCA("CA1");
		assertEquals(12, ca.getCAId());
		assertEquals("CA1", ca.getName());
		ca = CACacheManager.instance().getCA(13);
		assertEquals(13, ca.getCAId());
		assertEquals("CA2", ca.getName());
		ca = CACacheManager.instance().getCA("CA2");
		assertEquals(13, ca.getCAId());
		assertEquals("CA2", ca.getName());
		ca = CACacheManager.instance().getCA(14);
		assertNull(ca);
		ca = CACacheManager.instance().getCA("CA12");
		assertNull(ca);
		
		// plain remove
		CACacheManager.instance().removeCA(12);
		ca = CACacheManager.instance().getCA(12);
		assertNull(ca);
		ca = CACacheManager.instance().getCA("CA1");
		assertNull(ca);

		// Add new CA but with same CAId as an old one
		ca1.setName("CA3");
		CACacheManager.instance().addCA(12, ca1);
		ca = CACacheManager.instance().getCA(12);
		assertEquals(12, ca.getCAId());
		assertEquals("CA3", ca.getName());
		ca = CACacheManager.instance().getCA("CA3");
		assertEquals(12, ca.getCAId());
		assertEquals("CA3", ca.getName());

		// Rename CA
		ca1.setName("CA4");
		CACacheManager.instance().addCA(12, ca1);
		ca = CACacheManager.instance().getCA(12);
		assertEquals(12, ca.getCAId());
		assertEquals("CA4", ca.getName());
		ca = CACacheManager.instance().getCA("CA4");
		assertEquals(12, ca.getCAId());
		assertEquals("CA4", ca.getName());
	}
}
