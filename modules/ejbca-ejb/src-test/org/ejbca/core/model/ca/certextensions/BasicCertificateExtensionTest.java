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

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * @version $Id$
 */
public class BasicCertificateExtensionTest extends TestCase {
	private static Logger log = Logger.getLogger(BasicCertificateExtensionTest.class);
	
	public void test01NullBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERNULL");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = baseExt.getValue(null, null, null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DERNull);
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());
	}
	
	public void test02IntegerBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERINTEGER");
		props.put("id1.property.value", "1234");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = baseExt.getValue(null, null, null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DERInteger);
		assertTrue(((DERInteger)value).toString(),((DERInteger)value).toString().equals("1234"));
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());	
		
		props = new Properties();
		props.put("id1.property.encoding", "DERINTEGER");
		props.put("id1.property.value", "123SA4");
		boolean exceptionThrown = false;
		try{
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", false, props);
		  value = baseExt.getValue(null, null, null, null, null);
		}catch(CertificateExtentionConfigurationException e){
			exceptionThrown = true;
		}
		assertTrue(exceptionThrown);
	
	}
	
	public void test03BitStringBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERBITSTRING");
		props.put("id1.property.value", "1111"); // this is 15 decimal
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);		
		byte[] result = {15};
		DEREncodable value = baseExt.getValue(null, null, null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DERBitString);
		assertEquals(((DERBitString)value).getBytes()[0],result[0]);
		assertEquals(((DERBitString)value).getPadBits(), 0);
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());	
		
		props = new Properties();
		props.put("id1.property.encoding", "DERBITSTRING");
		// SSL Client and S/MIME in NetscapeCertType
		// This will be -96 in decimal, don't ask me why, but it is!
		props.put("id1.property.value", "10100000"); 
		
		baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		value = baseExt.getValue(null, null, null, null, null);
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
	}	
	
	public void test04BooleanBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERBOOLEAN");
		props.put("id1.property.value", "true");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = baseExt.getValue(null, null, null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DERBoolean);
		assertTrue(((DERBoolean)value).toString(),((DERBoolean)value).toString().equals("TRUE"));
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());			
		
        props.put("id1.property.value", "false");
		
		baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		value = baseExt.getValue(null, null, null, null, null);		
		assertTrue(((DERBoolean)value).toString(),((DERBoolean)value).toString().equals("FALSE"));
		
		props = new Properties();
		props.put("id1.property.encoding", "DERBOOLEAN");
		props.put("id1.property.value", "1sdf");
		boolean exceptionThrown = false;
		try{
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", false, props);
		  value = baseExt.getValue(null, null, null, null, null);
		}catch(CertificateExtentionConfigurationException e){
			exceptionThrown = true;
		}
		assertTrue(exceptionThrown);		
	}
	
	public void test05OctetBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DEROCTETSTRING");
		props.put("id1.property.value", "DBE81232");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = baseExt.getValue(null, null, null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DEROctetString);
		assertTrue(((DEROctetString)value).toString(),((DEROctetString)value).toString().equalsIgnoreCase("#DBE81232"));
		
		props = new Properties();
		props.put("id1.property.encoding", "DEROCTETSTRING");
		props.put("id1.property.value", "123SA4");
		boolean exceptionThrown = false;
		try{	
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", false, props);
		  value = baseExt.getValue(null, null, null, null, null);		  
		}catch(CertificateExtentionConfigurationException e){
			exceptionThrown = true;
		}
		assertTrue(exceptionThrown);

	}	
	
	public void test06PritableStringExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERPRINTABLESTRING");
		props.put("id1.property.value", "This is a printable string");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = baseExt.getValue(null, null, null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DERPrintableString);
		assertTrue(((DERPrintableString)value).toString(),((DERPrintableString)value).toString().equals("This is a printable string"));
		
		props = new Properties();
		props.put("id1.property.encoding", "DERPRINTABLESTRING");
		props.put("id1.property.value", "This is a non  printable string ���");
		boolean exceptionThrown = false;
		try{	
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", false, props);
		  value = baseExt.getValue(null, null, null, null, null);
		}catch(CertificateExtentionConfigurationException e){
			exceptionThrown = true;
		}
		assertTrue(exceptionThrown);
        
	}
	
	public void test07UTF8StringExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERUTF8STRING");
		props.put("id1.property.value", "This is a utf8 ��� ��string");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = baseExt.getValue(null, null, null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DERUTF8String);
		assertTrue(((DERUTF8String)value).getString(),((DERUTF8String)value).getString().equals("This is a utf8 ��� ��string"));
        
	}
	
	public void test08WrongEncoding() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERUTF8sdfTRING");
		props.put("id1.property.value", "This is a utf8 ��� ��string");

		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		boolean exceptionThrown =false;
		try{	

			baseExt.getValue(null, null, null, null, null);
		}catch(CertificateExtentionConfigurationException e){
			exceptionThrown = true;
		}
		assertTrue(exceptionThrown);
	}
	
	public void test09OidExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERBOJECTIDENTIFIER");
		props.put("id1.property.value", "1.1.1.255.1");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = baseExt.getValue(null, null, null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DERObjectIdentifier);
		assertTrue(((DERObjectIdentifier)value).getId(),((DERObjectIdentifier)value).getId().equals("1.1.1.255.1"));        
	}

	public void test10SequencedExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERUTF8STRING "); // Also test that we ignore spaces in the end here
		props.put("id1.property.nvalues", "3"); 
		props.put("id1.property.value1", "foo1");
		props.put("id1.property.value2", "foo2");
		props.put("id1.property.value3", "foo3");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = baseExt.getValue(null, null, null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DERSequence);
		DERSequence seq = (DERSequence)value;
		assertEquals(3, seq.size());
		Enumeration e = seq.getObjects();
		int i = 1;
		while(e.hasMoreElements()) {
			DEREncodable v = (DEREncodable)e.nextElement();
			assertTrue(v.getClass().toString(),v instanceof DERUTF8String);
			String str = ((DERUTF8String)v).getString();
			log.info(str);
			assertEquals(str,"foo"+i++);        
		}
	}

}
