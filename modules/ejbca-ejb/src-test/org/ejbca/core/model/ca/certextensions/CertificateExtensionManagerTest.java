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

package org.ejbca.core.model.ca.certextensions;

import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import junit.framework.TestCase;

import org.bouncycastle.asn1.DERPrintableString;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.util.StringTools;

/**
 * 
 * Test the functionality of the CertificateExtensionManager
 * 
 * @author Philip Vendil 2007 jan 7
 *
 * @version $Id$
 */

public class CertificateExtensionManagerTest extends TestCase {
	

	
	public void test01CertificateExtensionFactory() throws Exception{
	    Properties props = new Properties();
	    props.put("id1.oid", "1.2.3.4");
	    props.put("id1.classpath", "org.ejbca.core.model.ca.certextensions.BasicCertificateExtension");
	    props.put("id1.displayname", "TESTEXTENSION");
	    props.put("id1.used", "TRUE");
	    props.put("id1.translatable", "FALSE");
	    props.put("id1.critical", "TRUE");	    
	    props.put("id1.property.encoding", "DERPRINTABLESTRING");
	    props.put("id1.property.value", "Test 123");
	    
	    props.put("id2.oid", "2.2.3.4");
	    props.put("id2.classpath", "org.ejbca.core.model.ca.certextensions.BasicCertificateExtension");
	    props.put("id2.displayname", "TESTEXTENSION2");
	    props.put("id2.used", "false");
	    props.put("id2.translatable", "FALSE");
	    props.put("id2.critical", "TRUE");
	    props.put("id2.property.encoding", "DERPRINTABLESTRING");
	    props.put("id2.property.value", "Test 123");

	    props.put("id3.oid", "3.2.3.4");
	    props.put("id3.classpath", "org.ejbca.core.model.ca.certextensions.DummyAdvancedCertificateExtension");
	    props.put("id3.displayname", "TESTEXTENSION3");
	    props.put("id3.used", "TRUE");
	    props.put("id3.translatable", "TRUE");
	    props.put("id3.critical", "FALSE");
	    props.put("id3.property.value", "Test 321");		
		
		CertificateExtensionFactory fact = CertificateExtensionFactory.getInstance(props);
		
		assertTrue(fact.getAvailableCertificateExtensions().size()+"",fact.getAvailableCertificateExtensions().size() ==2);
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
		
		CertificateExtension certExt = fact.getCertificateExtensions(new Integer(1));
		assertTrue(certExt != null);
		assertTrue(certExt.getId() == 1);
		assertTrue(certExt.getOID().equals("1.2.3.4"));
		assertTrue(certExt.isCriticalFlag());
		assertTrue(certExt.getValue(null, null, null, null, null) instanceof DERPrintableString);
		assertTrue(((DERPrintableString) certExt.getValue(null, null, null, null, null)).getString().equals("Test 123"));
		
		assertNull(fact.getCertificateExtensions(new Integer(2)));
		
		certExt = fact.getCertificateExtensions(new Integer(3));
		assertTrue(certExt != null);
		assertTrue(certExt.getId() == 3);
		assertTrue(certExt.getOID().equals("3.2.3.4"));
		assertTrue(!certExt.isCriticalFlag());
		assertTrue(certExt.getValue(null, null, null, null, null) instanceof DERPrintableString);
		assertTrue(((DERPrintableString) certExt.getValue(null, null, null, null, null)).getString().equals("Test 321"));
		
	}
	
	public void test02StandardCertificateExtensions() throws Exception{
		
		CertificateExtensionFactory fact = CertificateExtensionFactory.getInstance();
    	CertificateProfile profile = new CertificateProfile();
    	profile.setUseAuthorityInformationAccess(true);
    	profile.setUseCertificatePolicies(true);
    	profile.setUseCRLDistributionPoint(true);
    	profile.setUseFreshestCRL(true);
    	profile.setUseMicrosoftTemplate(true);
    	profile.setUseOcspNoCheck(true);
    	profile.setUseQCStatement(true);
    	profile.setUseExtendedKeyUsage(true);
    	profile.setUseSubjectDirAttributes(true);
        List usedStdCertExt = profile.getUsedStandardCertificateExtensions();
        assertEquals(usedStdCertExt.size(), 14);
        Iterator certStdExtIter = usedStdCertExt.iterator();
        while(certStdExtIter.hasNext()){
        	String oid = (String)certStdExtIter.next();
        	CertificateExtension certExt = fact.getStandardCertificateExtension(oid, profile);
        	assertNotNull(certExt);
        }
		
	}
	
	public void test03TestSplitURIs() throws Exception {
		assertEquals(Arrays.asList("aa;a", "bb;;;b", "cc"), StringTools.splitURIs("\"aa;a\";\"bb;;;b\";\"cc\""));
		assertEquals(Arrays.asList("aa", "bb;;;b", "cc"), StringTools.splitURIs("aa;\"bb;;;b\";\"cc\""));
		assertEquals(Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs("aa;bb;cc"));
		assertEquals(Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs("aa;bb;cc;"));
		assertEquals(Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs("aa   ;  bb;cc  "));	// Extra white-spaces
		assertEquals(Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs("  aa;bb ;cc;  "));	// Extra white-spaces
		assertEquals(Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs("aa;bb;;;;cc;"));
		assertEquals(Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs(";;;;;aa;bb;;;;cc;"));
		assertEquals(Arrays.asList("aa", "b", "c", "d", "e"), StringTools.splitURIs(";;\"aa\";;;b;c;;;;d;\"e\";;;"));
		assertEquals(Arrays.asList("http://example.com"), StringTools.splitURIs("http://example.com"));
		assertEquals(Arrays.asList("http://example.com"), StringTools.splitURIs("\"http://example.com\""));
		assertEquals(Arrays.asList("http://example.com"), StringTools.splitURIs("\"http://example.com\";"));
		assertEquals(Collections.EMPTY_LIST, StringTools.splitURIs(""));
		assertEquals(Arrays.asList("http://example.com"), StringTools.splitURIs("\"http://example.com")); 	// No ending quote
		assertEquals(Arrays.asList("aa;a", "bb;;;b", "cc"), StringTools.splitURIs("\"aa;a\";\"bb;;;b\";\"cc")); 	// No ending quote
	}


}
