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
package org.cesecore.certificates.certificate.certextensions;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Iterator;
import java.util.List;

import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.junit.Test;

/**
 * 
 * Test the functionality of the CertificateExtensionManager
 * 
 * Based on EJBCA version: CertificateExtensionManagerTest.java 10397 2010-11-08 14:18:57Z anatom
 * 
 * @version $Id$
 */
public class CertificateExtensionFactoryTest {
	
	@Test
	public void test02StandardCertificateExtensions() throws Exception{
		
        // Reset before test
        CertificateExtensionFactory.resetExtensions();
		CertificateExtensionFactory fact = CertificateExtensionFactory.getInstance();
    	CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    	profile.setUseAuthorityInformationAccess(true);
    	profile.setUseCertificatePolicies(true);
    	profile.setUseCRLDistributionPoint(true);
    	profile.setUseFreshestCRL(true);
    	profile.setUseMicrosoftTemplate(true);
    	profile.setUseOcspNoCheck(true);
    	profile.setUseQCStatement(true);
    	profile.setUseExtendedKeyUsage(true);
    	profile.setUseSubjectDirAttributes(true);
    	profile.setUsePrivateKeyUsagePeriodNotBefore(true);
    	profile.setUsePrivateKeyUsagePeriodNotAfter(true);
        List<String> usedStdCertExt = profile.getUsedStandardCertificateExtensions();
        assertEquals(16, usedStdCertExt.size());
        Iterator<String> certStdExtIter = usedStdCertExt.iterator();
        while(certStdExtIter.hasNext()){
        	String oid = certStdExtIter.next();
        	CertificateExtension certExt = fact.getStandardCertificateExtension(oid, profile);
        	assertNotNull(certExt);
        }
		
	}

}
