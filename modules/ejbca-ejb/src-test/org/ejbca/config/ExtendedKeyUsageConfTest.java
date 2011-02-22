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

package org.ejbca.config;

import java.io.File;
import java.io.FileWriter;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

/**
 * Tests the ExtendedKeyUsageConfiguration class
 * 
 * @version $Id$
 */
public class ExtendedKeyUsageConfTest extends TestCase {
	
	public ExtendedKeyUsageConfTest(String name) {
		super(name);
		ConfigurationHolder.instance().clear();
	}

	public void test01GetOids() throws Exception {
		// Create some values in a temp file and add to the configuration
		File f = File.createTempFile("testextendedkeyusageconf", "properties");
		f.deleteOnExit();
		FileWriter fos = new FileWriter(f);
		fos.write("extendedkeyusage.oid.0 = 2.5.29.37.0\nextendedkeyusage.name.0 = EKU_PKIX_ANYEXTENDEDKEYUSAGE\n");
		fos.write("extendedkeyusage.oid.1 = 1.3.6.1.5.5.7.3.21\nextendedkeyusage.name.1 = EKU_PKIX_SSHCLIENT\n");
		fos.write("extendedkeyusage.oid.2 = 1.2.840.113583.1.1.5\nextendedkeyusage.name.2 = EKU_ADOBE_PDFSIGNING\n");
		fos.close();
		ConfigurationHolder.addConfigurationFile(f.getAbsolutePath());
		// Now there will be some values
		List<String> oids = ExtendedKeyUsageConfiguration.getExtendedKeyUsageOids();
		assertEquals(3, oids.size()); 
		Map<String, String> map = ExtendedKeyUsageConfiguration.getExtendedKeyUsageOidsAndNames();
		assertTrue(oids.contains("2.5.29.37.0")); // EKU_PKIX_ANYEXTENDEDKEYUSAGE
		assertEquals("EKU_PKIX_ANYEXTENDEDKEYUSAGE", map.get("2.5.29.37.0"));
		assertTrue(oids.contains("1.3.6.1.5.5.7.3.21")); // EKU_PKIX_SSHCLIENT
		assertEquals("EKU_PKIX_SSHCLIENT", map.get("1.3.6.1.5.5.7.3.21"));
		assertTrue(oids.contains("1.2.840.113583.1.1.5")); // EKU_ADOBE_PDFSIGNING
		assertEquals("EKU_ADOBE_PDFSIGNING", map.get("1.2.840.113583.1.1.5"));
	}
	
}
