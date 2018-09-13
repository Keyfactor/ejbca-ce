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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.internal.InternalResources;
import org.junit.Test;

/**
 * @version $Id$
 */
public class BasicCertificateExtensionTest {
    private static Logger log = Logger.getLogger(BasicCertificateExtensionTest.class);
	
    private static final InternalResources intres = InternalResources.getInstance();
        
	@Test
	public void test01NullBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("encoding", "DERNULL");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		
		ASN1Encodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERNull);
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());
	}

	@Test
	public void test02IntegerBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("encoding", "DERINTEGER");
		props.put("value", "1234");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		
		ASN1Encodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof ASN1Integer);
		assertTrue(((ASN1Integer)value).toString(),((ASN1Integer)value).toString().equals("1234"));
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());	
		
		props = new Properties();
		props.put("encoding", "DERINTEGER");
		props.put("value", "123SA4");
		boolean exceptionThrown = false;
		try{
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		  value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		}catch(CertificateExtensionException e){
			exceptionThrown = true;
			assertEquals(intres.getLocalizedMessage("certext.basic.illegalvalue", "123SA4", 1, "1.2.3"), e.getMessage());
		}
		assertTrue(exceptionThrown);
	
	}

	@Test
	public void test03BitStringBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("encoding", "DERBITSTRING");
		props.put("value", "1111"); // this is 15 decimal
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);		
		byte[] result = {15};
		ASN1Encodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERBitString);
		assertEquals(((DERBitString)value).getBytes()[0],result[0]);
		assertEquals(((DERBitString)value).getPadBits(), 0);
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());	
		
		props = new Properties();
		props.put("encoding", "DERBITSTRING");
		// SSL Client and S/MIME in NetscapeCertType
		// This will be -96 in decimal, don't ask me why, but it is!
		props.put("value", "10100000"); 
		
		baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERBitString);
		new BigInteger(((DERBitString)value).getBytes()); // Will throw if value is wrong
		//log.debug(bi.toString(2));
		//log.debug(bi.toString());
		//log.debug(((DERBitString)value).getBytes()[0]);
		assertEquals(((DERBitString)value).getBytes()[0],-96);
		assertEquals(((DERBitString)value).getPadBits(), 5);
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());	

		// Test error
		props = new Properties();
		props.put("encoding", "DERBITSTRING");
		props.put("value", "qqqq");
		baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		try {
			value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
			assertTrue("Should throw", false);
		} catch (CertificateExtensionException e) {
			assertEquals(intres.getLocalizedMessage("certext.basic.illegalvalue", "qqqq", 1, "1.2.3"), e.getMessage());
		}

	}	
	
	@Test
	public void test04BooleanBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("encoding", "DERBOOLEAN");
		props.put("value", "true");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		
		ASN1Encodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof ASN1Boolean);
		assertTrue(((ASN1Boolean)value).toString(),((ASN1Boolean)value).toString().equals("TRUE"));
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());			
		
        props.put("value", "false");
		
		baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		
		value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));		
		assertTrue(((ASN1Boolean)value).toString(),((ASN1Boolean)value).toString().equals("FALSE"));
		
		props = new Properties();
		props.put("encoding", "DERBOOLEAN");
		props.put("value", "1sdf");
		boolean exceptionThrown = false;
		try{
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		  value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		}catch(CertificateExtensionException e){
			exceptionThrown = true;
                        assertEquals(intres.getLocalizedMessage("certext.basic.illegalvalue", "1sdf", 1, "1.2.3"), e.getMessage());
		}
		assertTrue(exceptionThrown);		
	}
	
	@Test
	public void test05OctetBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("encoding", "DEROCTETSTRING");
		props.put("value", "DBE81232");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		
		ASN1Encodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DEROctetString);
		assertTrue(((DEROctetString)value).toString(),((DEROctetString)value).toString().equalsIgnoreCase("#DBE81232"));
		
		props = new Properties();
		props.put("encoding", "DEROCTETSTRING");
		props.put("value", "123SA4");
		boolean exceptionThrown = false;
		try{	
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		  value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));		  
		}catch(CertificateExtensionException e){
			exceptionThrown = true;
                        assertEquals(intres.getLocalizedMessage("certext.basic.illegalvalue", "123SA4", 1, "1.2.3"), e.getMessage());
		}
		assertTrue(exceptionThrown);

	}	
	
	@Test
	public void test06PritableStringExtension() throws Exception{
		Properties props = new Properties();
		props.put("encoding", "DERPRINTABLESTRING");
		props.put("value", "This is a printable string");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		
		ASN1Encodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERPrintableString);
		assertTrue(((DERPrintableString)value).toString(),((DERPrintableString)value).toString().equals("This is a printable string"));
		
		props = new Properties();
		props.put("encoding", "DERPRINTABLESTRING");
		props.put("value", "This is a non  printable string åäöüè");
		boolean exceptionThrown = false;
		try{	
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		  value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		}catch(CertificateExtensionException e){
			exceptionThrown = true;
			assertEquals(intres.getLocalizedMessage("certext.basic.illegalvalue", "This is a non  printable string åäöüè", 1, "1.2.3"), e.getMessage());
			// Verify with unicode encoded as well to ensure file encodings were not just messed up
            assertEquals(intres.getLocalizedMessage("certext.basic.illegalvalue", "This is a non  printable string \u00E5\u00E4\u00F6\u00FC\u00E8", 1, "1.2.3"), e.getMessage());
		}
		assertTrue(exceptionThrown);        
	}
	
	@Test
	public void test07UTF8StringExtension() throws Exception{
		Properties props = new Properties();
		props.put("encoding", "DERUTF8STRING");
		props.put("value", "This is a utf8 åäöüè string");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		
		ASN1Encodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERUTF8String);
		assertTrue(((DERUTF8String)value).getString(),((DERUTF8String)value).getString().equals("This is a utf8 åäöüè string"));
        
	}
	
	@Test
	public void test08WrongEncoding() throws Exception{
		Properties props = new Properties();
		props.put("encoding", "DERUTF8sdfTRING");
		props.put("value", "This is a utf8 åäöüè string");

		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		try{
			baseExt.getValueEncoded(null, null, null, null, null, null);
			assertTrue("Should throw", false);		
		}catch(CertificateExtensionException e){
			assertEquals(intres.getLocalizedMessage("certext.basic.incorrectenc", "DERUTF8sdfTRING", 1), e.getMessage());
		}
		
		Properties props1 = new Properties();
		props1.put("encoding", "DERUTF8STRING");
		props1.put("value", "");

		BasicCertificateExtension baseExt1 = new BasicCertificateExtension();
		baseExt1.init(1, "1.2.3", "BasicCertificateExtension", false, true, props1);
		try{
			baseExt1.getValueEncoded(null, null, null, null, null, null);
			assertTrue("Should throw", false);		
		}catch(CertificateExtensionException e){
			// NOPMD
		}
	}
	
	@Test
	public void test09OidExtension() throws Exception{
		Properties props = new Properties();
		props.put("encoding", "DERBOJECTIDENTIFIER");
		props.put("value", "1.1.1.255.1");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		
		ASN1Encodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof ASN1ObjectIdentifier);
		assertTrue(((ASN1ObjectIdentifier)value).getId(),((ASN1ObjectIdentifier)value).getId().equals("1.1.1.255.1"));
		
		props = new Properties();
		props.put("encoding", "DERBOJECTIDENTIFIER");
		props.put("value", "3.1.1.255.1"); // Illegal oid, must be 0-2 in first char
	
		baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);		
		try{
			baseExt.getValueEncoded(null, null, null, null, null, null);
			assertTrue("Should throw", false);		
		}catch(CertificateExtensionException e){
			// NOPMD
		}
	}

	@Test
	public void test10SequencedExtension() throws Exception{
		Properties props = new Properties();
		props.put("encoding", "DERUTF8STRING "); // Also test that we ignore spaces in the end here
		props.put("nvalues", "3"); 
		props.put("value1", "foo1");
		props.put("value2", "foo2");
		props.put("value3", "foo3");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		
		ASN1Encodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DLSequence);
		DLSequence seq = (DLSequence)value;
		assertEquals(3, seq.size());
		@SuppressWarnings("unchecked")
        Enumeration<ASN1Encodable> e = seq.getObjects();
		int i = 1;
		while(e.hasMoreElements()) {
			ASN1Encodable v = e.nextElement();
			assertTrue(v.getClass().toString(),v instanceof DERUTF8String);
			String str = ((DERUTF8String)v).getString();
			log.info(str);
			assertEquals(str,"foo"+i++);        
		}
	}

	@Test
	public void test11IA5StringExtension() throws Exception{
		Properties props = new Properties();
		props.put("encoding", "DERIA5STRING");
		props.put("value", "This is a printable string");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		
		ASN1Encodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERIA5String);
		assertEquals("This is a printable string", ((DERIA5String)value).toString());
		
		props = new Properties();
		props.put("encoding", "DERIA5STRING");
		props.put("value", "This is a non printable string åäöüè");
		boolean exceptionThrown = false;
		try{	
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		  value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		}catch(CertificateExtensionException e){
			exceptionThrown = true;
		}
		assertTrue(exceptionThrown);        
	}

	@Test
	public void test12DERObjectExtension() throws Exception{
		Properties props = new Properties();
		props.put("encoding", "DEROBJECT");
		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(new DERPrintableString("foo1"));
		vec.add(new DERPrintableString("foo2"));
		vec.add(new DERPrintableString("foo3"));
		DERSet set = new DERSet(vec);
		String str = new String(Hex.encode(set.getEncoded()));
		props.put("value", str);
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		
		ASN1Encodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DLSet);
		DLSet set1 = (DLSet)value;
		assertEquals(3, set1.size());
		
		props = new Properties();
		props.put("encoding", "DEROBJECT");
		props.put("value", "This is not an asn1 hex encoded object");
		baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		try{	
		  value = getObject(baseExt.getValueEncoded(null, null, null, null, null, null));
		  assertTrue("Should throw", false);
		}catch(CertificateExtensionException e){
			// NOPMD
		}
	}
        
	/**
	 * Test with dynamic=true and no static value specified.
	 *
	 * There should be an exception if no value was specified in ExtendedInformation.
	 * But it should succeed if an value was specified in ExtendedInformation.
	 */
	@Test
	public void test13DynamicTrueNoStatic() throws Exception {
		Properties props = new Properties();
		props.put("encoding", "DERPRINTABLESTRING");
		props.put("dynamic", "true");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		EndEntityInformation userData = new EndEntityInformation();
		userData.setExtendedInformation(new ExtendedInformation());
		
		// Fail without value specified
		try {
			baseExt.getValueEncoded(userData, null, null, null, null, null);
			fail("Should have failed as no value was specified in EI.");
		} catch (CertificateExtensionException ex) {
			assertEquals(intres.getLocalizedMessage("certext.basic.incorrectvalue", 1, "1.2.3"), ex.getMessage());
		}
		
		// Success with value specified
		userData.getExtendedInformation().setExtensionData("1.2.3", "The value 123");
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null, null)));
        try {
            ASN1Encodable value1 = in.readObject();
            assertTrue(value1.getClass().toString(), value1 instanceof DERPrintableString);
            assertEquals("The value 123", ((DERPrintableString) value1).getString());
        } finally {
            in.close();
        }
		
	}
	
	/**
	 * Test with dynamic=true and and a static value specified.
	 *
	 * The static value should be used if no value was specified in ExtendedInformation.
	 * The value from ExtendedInformation should be used if present.
	 */
    @Test
	public void test14DynamicTrueStatic() throws Exception {
		Properties props = new Properties();
		props.put("encoding", "DERPRINTABLESTRING");
		props.put("dynamic", "true");
		props.put("value", "The static value 123");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		EndEntityInformation userData = new EndEntityInformation();
		userData.setExtendedInformation(new ExtendedInformation());
		
		// Without value in userdata, the static value is used
		ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null, null)));
		ASN1Encodable value1 = in.readObject();
		assertTrue(value1.getClass().toString(), value1 instanceof DERPrintableString);
		assertEquals("The static value 123", ((DERPrintableString) value1).getString());
		
		// With value in userdata, that value is used
		userData.getExtendedInformation().setExtensionData("1.2.3", "A dynamic value 123");
		in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null, null)));
		value1 = in.readObject();
		assertTrue(value1.getClass().toString(), value1 instanceof DERPrintableString);
		assertEquals("A dynamic value 123", ((DERPrintableString) value1).getString());
	}
	
	/**
	 * Test with dynamic=true and and a static value specified where nvalues are used.
	 *
	 * The static values should be used if no value was specified in ExtendedInformation.
	 * The values from ExtendedInformation should be used if present.
	 */
    @SuppressWarnings("unchecked")
    @Test
	public void test15DynamicTrueStaticNvalues() throws Exception {
		Properties props = new Properties();
		props.put("encoding", "DERPRINTABLESTRING");
		props.put("dynamic", "true");
		props.put("nvalues", "3");
		props.put("value1", "The static value 1");
		props.put("value2", "The static value 2");
		props.put("value3", "The static value 3");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		EndEntityInformation userData = new EndEntityInformation();
		userData.setExtendedInformation(new ExtendedInformation());
		
		// Without value in userdata, the static values is used
		ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null, null)));
		ASN1Encodable value = in.readObject();
		assertTrue(value.getClass().toString(),value instanceof DLSequence);
		DLSequence seq = (DLSequence)value;
		assertEquals(3, seq.size());
        Enumeration<ASN1Encodable> e = seq.getObjects();
		int i = 1;
		while (e.hasMoreElements()) {
		    ASN1Encodable v = e.nextElement();
			assertTrue(v.getClass().toString(), v instanceof DERPrintableString);
			String str = ((DERPrintableString) v).getString();
			assertEquals(str, "The static value " + i++);        
		}
		
		// With values in userdata, that values is used
		userData.getExtendedInformation().setExtensionData("1.2.3.value1", "A dynamic value 1");
		userData.getExtendedInformation().setExtensionData("1.2.3.value2", "A dynamic value 2");
		userData.getExtendedInformation().setExtensionData("1.2.3.value3", "A dynamic value 3");
		in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null, null)));
		value = in.readObject();
		assertTrue(value.getClass().toString(),value instanceof DLSequence);
		seq = (DLSequence)value;
		assertEquals(3, seq.size());
		e = seq.getObjects();
		i = 1;
		while (e.hasMoreElements()) {
			ASN1Encodable v = (ASN1Encodable)e.nextElement();
			assertTrue(v.getClass().toString(), v instanceof DERPrintableString);
			String str = ((DERPrintableString) v).getString();
			assertEquals(str, "A dynamic value " + i++);        
		}
	}
	
	/**
	 * Test that without dynamic specified it defaults to dynamic=false.
	 *
	 * The static value should be used regardless of there was a value in 
	 * ExtendedInformation or not.
	 */
    @Test
	public void test16DynamicDefaultsToFalse() throws Exception {
		Properties props = new Properties();
		props.put("encoding", "DERPRINTABLESTRING");
		props.put("value", "The static value");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		EndEntityInformation userData = new EndEntityInformation();
		userData.setExtendedInformation(new ExtendedInformation());
		
		// Ok without value specified
		ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null, null)));
		ASN1Encodable value1 = in.readObject();
		assertTrue(value1.getClass().toString(), value1 instanceof DERPrintableString);
		assertEquals("The static value", ((DERPrintableString) value1).getString());
		
		// Ignoring dynamic value specified
		userData.getExtendedInformation().setExtensionData("1.2.3", "The value 123");
		in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null, null)));
		value1 = in.readObject();
		assertTrue(value1.getClass().toString(), value1 instanceof DERPrintableString);
		assertEquals("The static value", ((DERPrintableString) value1).getString());
	}
	
	/**
	 * Same as test16DynamicDefaultsToFalse but with dynamic explicitly set to
	 *  false.
	 */
    @Test
	public void test17DynamicFalse() throws Exception {
		Properties props = new Properties();
		props.put("encoding", "DERPRINTABLESTRING");
		props.put("value", "The static value");
		props.put("dynamic", "false");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		EndEntityInformation userData = new EndEntityInformation();
		userData.setExtendedInformation(new ExtendedInformation());
		
		// Ok without value specified
		ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null, null)));
		ASN1Encodable value = in.readObject();
		assertTrue(value.getClass().toString(), value instanceof DERPrintableString);
		assertEquals("The static value", ((DERPrintableString) value).getString());
		
		// Ignoring dynamic value specified
		userData.getExtendedInformation().setExtensionData("1.2.3", "The value 123");
		in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null, null)));
		value = in.readObject();
		assertTrue(value.getClass().toString(), value instanceof DERPrintableString);
		assertEquals("The static value", ((DERPrintableString) value).getString());
	}
	
	/**
	 * Test with dynamic=true and value specified with key 1.2.3.value=.
	 */
    @Test
	public void test18DynamicValueValue() throws Exception {
		Properties props = new Properties();
		props.put("encoding", "DERPRINTABLESTRING");
		props.put("dynamic", "true");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		EndEntityInformation userData = new EndEntityInformation();
		userData.setExtendedInformation(new ExtendedInformation());
		
		// Success with value specified
		userData.getExtendedInformation().setExtensionData("1.2.3.value", "The value 456");
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null, null)));
        try {
            ASN1Encodable value1 = in.readObject();
            assertTrue(value1.getClass().toString(), value1 instanceof DERPrintableString);
            assertEquals("The value 456", ((DERPrintableString) value1).getString());
        } finally {
            in.close();
        }
	}
	
    /**
     * Test using encoding=RAW and both dynamic and static value.
     */
    @Test
	public void test19RawValue() throws Exception {
		Properties props = new Properties();
		props.put("encoding", "RAW");
		props.put("dynamic", "true");
		props.put("value", "aabbccdd");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		EndEntityInformation userData = new EndEntityInformation();
		userData.setExtendedInformation(new ExtendedInformation());
		
		// Without value in userdata, the static value is used
		byte[] value = baseExt.getValueEncoded(userData, null, null, null, null, null);
		assertEquals("value", "aabbccdd", new String(Hex.encode(value)));
		
		// With value in userdata, that value is used
		userData.getExtendedInformation().setExtensionData("1.2.3", "eeff0000");
		value = baseExt.getValueEncoded(userData, null, null, null, null, null);
		assertEquals("value", "eeff0000", new String(Hex.encode(value)));
	}

    @Test
    public void test20CertExtensionEncoding() throws Exception{
        Properties props = new Properties();
        props.put("encoding", "DERIA5STRING");
        props.put("value", "This is a printable string");
        
        BasicCertificateExtension baseExt = new BasicCertificateExtension();
        baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
        
        byte[] value = baseExt.getValueEncoded(null, null, null, null, null, null);
        
        ExtensionsGenerator extgen = new ExtensionsGenerator();
        extgen.addExtension(new ASN1ObjectIdentifier(baseExt.getOID()), baseExt.isCriticalFlag(), value);
        Extensions exts = extgen.generate();
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(baseExt.getOID());
        Extension ext = exts.getExtension(oid);
        assertNotNull(ext);
        // Read the extension value, it's a DERIA5String wrapped in an ASN1OctetString
        ASN1OctetString str = ext.getExtnValue();
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(str.getOctets()));
        DERIA5String ia5str = (DERIA5String)aIn.readObject();
        aIn.close();
        assertEquals("This is a printable string", ia5str.getString());
    }

    private ASN1Encodable getObject(byte[] valueEncoded) throws IOException {
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(valueEncoded));
        try {
            return in.readObject();
        } finally {
            in.close();
        }
    }

    /**
     * Test using encoding=RAW and only dynamic value.
     */
    @Test
	public void test21RawValueNotSpecified() throws Exception {
		Properties props = new Properties();
		props.put("encoding", "RAW");
		props.put("dynamic", "true");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		EndEntityInformation userData = new EndEntityInformation();
		userData.setExtendedInformation(new ExtendedInformation());
		
		// Without value in userdata it should fail
		try {
		    baseExt.getValueEncoded(userData, null, null, null, null, null);
		    fail("Should have fail as no dynamic value specified");
		} catch (CertificateExtensionException ex) {
		    assertEquals(intres.getLocalizedMessage("certext.basic.incorrectvalue", 1, "1.2.3"), ex.getMessage());
		}
		
		// With value in userdata, that value is used
		userData.getExtendedInformation().setExtensionData("1.2.3", "eeff0000");
		byte[] value = baseExt.getValueEncoded(userData, null, null, null, null, null);
		assertEquals("value", "eeff0000", new String(Hex.encode(value)));
    }
        
    /**
     * Test without any value specified.
     */
    @Test
    public void test22ValueNotSpecified() throws Exception{
        Properties props = new Properties();
		props.put("encoding", "DERINTEGER");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		
		try {
		    baseExt.getValueEncoded(null, null, null, null, null, null);
		    fail("Should have fail as no value specified");
		} catch (CertificateExtensionException ex) {
		    assertEquals(intres.getLocalizedMessage("certext.basic.incorrectvalue", 1, "1.2.3"), ex.getMessage());
		}
	}
        
    /**
     * Test using encoding=RAW but nvalues > 1 specified which is a
     * configuration error.
     */
    @Test
	public void test23RawValueButNValues() throws Exception {
		Properties props = new Properties();
		props.put("encoding", "RAW");
		props.put("dynamic", "true");
                props.put("nvalues", "3"); 
		props.put("value1", "foo1");
		props.put("value2", "foo2");
		props.put("value3", "foo3");
                
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", "BasicCertificateExtension", false, true, props);
		EndEntityInformation userData = new EndEntityInformation();
		userData.setExtendedInformation(new ExtendedInformation());
		
		try {
		    baseExt.getValueEncoded(userData, null, null, null, null, null);
		    fail("Should have fail as both raw and nvalues specified");
		} catch (CertificateExtensionException ex) {
                    assertEquals(intres.getLocalizedMessage("certext.certextmissconfigured", 1), ex.getMessage());
		}
    }

}
