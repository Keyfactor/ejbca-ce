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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERPrintableString;
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
/*
	@Test
	public void test01CertificateExtensionFactory() throws Exception{
	    Properties props = new Properties();
	    props.put("id1.oid", "1.2.3.4");
	    props.put("id1.classpath", BasicCertificateExtension.class.getName());
	    props.put("id1.displayname", "TESTEXTENSION");
	    props.put("id1.used", "TRUE");
	    props.put("id1.translatable", "FALSE");
	    props.put("id1.critical", "TRUE");	    
	    props.put("id1.property.encoding", "DERPRINTABLESTRING");
	    props.put("id1.property.value", "Test 123");
	    
	    props.put("id2.oid", "2.2.3.4");
	    props.put("id2.classpath", BasicCertificateExtension.class.getName());
	    props.put("id2.displayname", "TESTEXTENSION2");
	    props.put("id2.used", "false");
	    props.put("id2.translatable", "FALSE");
	    props.put("id2.critical", "TRUE");
	    props.put("id2.property.encoding", "DERPRINTABLESTRING");
	    props.put("id2.property.value", "Test 123");

	    props.put("id3.oid", "3.2.3.4");
	    props.put("id3.classpath", DummyAdvancedCertificateExtension.class.getName());
	    props.put("id3.displayname", "TESTEXTENSION3");
	    props.put("id3.used", "TRUE");
	    props.put("id3.translatable", "TRUE");
	    props.put("id3.critical", "FALSE");
	    props.put("id3.property.value", "Test 321");		
		
	    // Reset before test
	    CertificateExtensionFactory.resetExtensions();
		CertificateExtensionFactory fact = CertificateExtensionFactory.getInstance(props);
		
		assertEquals(2, fact.getAvailableCertificateExtensions().size());
		AvailableCertificateExtension availExt = (AvailableCertificateExtension) fact.getAvailableCertificateExtensions().get(0);
		assertTrue(availExt.getId() == 1);
		assertTrue(availExt.getOID().equals("1.2.3.4"));
		assertTrue(availExt.getDisplayName().equals("TESTEXTENSION"));
		assertTrue(availExt.isTranslatable() == false);
		
		availExt = (AvailableCertificateExtension) fact.getAvailableCertificateExtensions().get(1);
		assertTrue(availExt.getId() == 3);
		assertTrue(availExt.getOID().equals("3.2.3.4"));
		assertTrue(availExt.getDisplayName().equals("TESTEXTENSION3"));
		assertTrue(availExt.isTranslatable() == true);
		
		CertificateExtension certExt = fact.getCertificateExtensions(Integer.valueOf(1));
		assertTrue(certExt != null);
		assertTrue(certExt.getId() == 1);
		assertTrue(certExt.getOID().equals("1.2.3.4"));
		assertTrue(certExt.isCriticalFlag());
		assertTrue(getObject(certExt.getValueEncoded(null, null, null, null, null, null)) instanceof DERPrintableString);
		assertTrue(((DERPrintableString) getObject(certExt.getValueEncoded(null, null, null, null, null, null))).getString().equals("Test 123"));
		
		assertNull(fact.getCertificateExtensions(Integer.valueOf(2)));
		
		certExt = fact.getCertificateExtensions(Integer.valueOf(3));
		assertTrue(certExt != null);
		assertTrue(certExt.getId() == 3);
		assertTrue(certExt.getOID().equals("3.2.3.4"));
		assertTrue(!certExt.isCriticalFlag());
		assertTrue(getObject(certExt.getValueEncoded(null, null, null, null, null, null)) instanceof DERPrintableString);
		assertTrue(((DERPrintableString) getObject(certExt.getValueEncoded(null, null, null, null, null, null))).getString().equals("Test 321"));
		
	}
*/	
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
	
	private ASN1Encodable getObject(byte[] valueEncoded) throws IOException {
		ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(valueEncoded));
        try {
            return in.readObject();
        } finally {
            in.close();
        }
	}

}
