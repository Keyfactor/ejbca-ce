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

package org.cesecore.config;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileWriter;

import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the OcspConfiguration class
 * 
 * @version $Id$
 */
public class OcspConfigurationTest {
	
	@Before
	public void setUp() {
		ConfigurationHolder.instance().clear();
	}

	@Test
	public void testMaxAgeNextUpdate() throws Exception {
		long maxAge = OcspConfiguration.getMaxAge(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
		long nextUpdate = OcspConfiguration.getUntilNextUpdate(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
		assertEquals(30000, maxAge);
		assertEquals(0, nextUpdate);
		
		// Create some values in a temp file and add to the configuration
		File f = File.createTempFile("testocspconf", "properties");
		f.deleteOnExit();
		FileWriter fos = new FileWriter(f);
		fos.write("ocsp.maxAge=60\nocsp.untilNextUpdate=70\nocsp.999.maxAge=70\nocsp.999.untilNextUpdate=80\nocsp.888.maxAge=75\nocsp.888.untilNextUpdate=85\n");
		fos.close();
		ConfigurationHolder.addConfigurationFile(f.getAbsolutePath());
		
		// New defaults
		maxAge = OcspConfiguration.getMaxAge(0);
		nextUpdate = OcspConfiguration.getUntilNextUpdate(0);
		assertEquals(60000, maxAge);
		assertEquals(70000, nextUpdate);
		// Our specified values
		maxAge = OcspConfiguration.getMaxAge(999);
		nextUpdate = OcspConfiguration.getUntilNextUpdate(999);
		assertEquals(70000, maxAge);
		assertEquals(80000, nextUpdate);
		maxAge = OcspConfiguration.getMaxAge(888);
		nextUpdate = OcspConfiguration.getUntilNextUpdate(888);
		assertEquals(75000, maxAge);
		assertEquals(85000, nextUpdate);
		// A profile that does not exist should use defaults
		maxAge = OcspConfiguration.getMaxAge(111);
		nextUpdate = OcspConfiguration.getUntilNextUpdate(111);
		assertEquals(60000, maxAge);
		assertEquals(70000, nextUpdate);
	}
	
}
