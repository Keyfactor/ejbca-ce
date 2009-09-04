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

package org.ejbca.core.model.ra;

import junit.framework.TestCase;

import org.bouncycastle.asn1.x509.X509Name;

/**
 * Test of the UserNameGenerator class.
 */
public class TestUserNameGenerator extends TestCase {

    public TestUserNameGenerator(String testName) {
        super(testName);
    }

    /**
     * Test user generation based on both SN and CN.
     */
	public void test01() throws Exception {
		UsernameGeneratorParams usernameGeneratorParams = new UsernameGeneratorParams();
		usernameGeneratorParams.setMode("DN");
		usernameGeneratorParams.setDNGeneratorComponent("SN;CN");
		usernameGeneratorParams.setPrefix(null);
		usernameGeneratorParams.setPostfix(null);
		UsernameGenerator usernameGenerator = UsernameGenerator.getInstance(usernameGeneratorParams);

		final String errorMessage = "Did not generate an expected username.";
		assertEquals(errorMessage, "test", usernameGenerator.generateUsername(new X509Name("CN=test").toString()));
		assertEquals(errorMessage, null, usernameGenerator.generateUsername("".toString()));
		assertEquals(errorMessage, null, usernameGenerator.generateUsername(" ".toString()));
		assertEquals(errorMessage, "test", usernameGenerator.generateUsername(new X509Name("CN=test, serialNumber=1234").toString()));
		assertEquals(errorMessage, null, usernameGenerator.generateUsername(new X509Name("O=org").toString()));
		assertEquals(errorMessage, "12345", usernameGenerator.generateUsername("CN=test, SN=12345"));
		assertEquals(errorMessage, "1234", usernameGenerator.generateUsername("SN=1234"));
		
		// These wont work since new X509Name converts SN to SERIALNUMBER in toString()
		// Is this something we should compensate for in CertTools.getPartFromDN(...) ?
		//assertEquals(errorMessage, "12345", usernameGenerator.generateUsername(new X509Name("CN=test, SN=12345").toString()));
		//assertEquals(errorMessage, "1234", usernameGenerator.generateUsername(new X509Name("SN=1234").toString()));
	}
}
