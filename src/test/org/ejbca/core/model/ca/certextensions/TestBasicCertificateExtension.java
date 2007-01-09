package org.ejbca.core.model.ca.certextensions;

import java.util.Properties;

import junit.framework.TestCase;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;

public class TestBasicCertificateExtension extends TestCase {

	
	public void test01NullBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERNULL");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = baseExt.getValue(null, null, null);
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
		
		DEREncodable value = baseExt.getValue(null, null, null);
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
		  value = baseExt.getValue(null, null, null);
		}catch(CertificateExtentionConfigurationException e){
			exceptionThrown = true;
		}
		assertTrue(exceptionThrown);
	
	}
	
	public void test03BitStringBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERBITSTRING");
		props.put("id1.property.value", "1111");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		byte[] result = {15};
		DEREncodable value = baseExt.getValue(null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DERBitString);
		assertTrue(((DERBitString)value).getBytes()[0]+"",((DERBitString)value).getBytes()[0] == result[0]);
		assertTrue(((DERBitString)value).getPadBits() == 4);
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
		
		DEREncodable value = baseExt.getValue(null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DERBoolean);
		assertTrue(((DERBoolean)value).toString(),((DERBoolean)value).toString().equals("TRUE"));
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());			
		
        props.put("id1.property.value", "false");
		
		baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		value = baseExt.getValue(null, null, null);		
		assertTrue(((DERBoolean)value).toString(),((DERBoolean)value).toString().equals("FALSE"));
		
		props = new Properties();
		props.put("id1.property.encoding", "DERBOOLEAN");
		props.put("id1.property.value", "1sdf");
		boolean exceptionThrown = false;
		try{
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", false, props);
		  value = baseExt.getValue(null, null, null);
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
		
		DEREncodable value = baseExt.getValue(null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DEROctetString);
		assertTrue(((DEROctetString)value).toString(),((DEROctetString)value).toString().equalsIgnoreCase("#DBE81232"));
		
		props = new Properties();
		props.put("id1.property.encoding", "DEROCTETSTRING");
		props.put("id1.property.value", "123SA4");
		boolean exceptionThrown = false;
		try{	
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", false, props);
		  value = baseExt.getValue(null, null, null);		  
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
		
		DEREncodable value = baseExt.getValue(null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DERPrintableString);
		assertTrue(((DERPrintableString)value).toString(),((DERPrintableString)value).toString().equals("This is a printable string"));
		
		props = new Properties();
		props.put("id1.property.encoding", "DERPRINTABLESTRING");
		props.put("id1.property.value", "This is a non  printable string Â‰ˆ");
		boolean exceptionThrown = false;
		try{	
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", false, props);
		  value = baseExt.getValue(null, null, null);
		}catch(CertificateExtentionConfigurationException e){
			exceptionThrown = true;
		}
		assertTrue(exceptionThrown);
        
	}
	
	public void test07UTF8StringExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERUTF8STRING");
		props.put("id1.property.value", "This is a utf8 Â‰ˆ  Ístring");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = baseExt.getValue(null, null, null);
		assertTrue(value.getClass().toString(),value instanceof DERUTF8String);
		assertTrue(((DERUTF8String)value).getString(),((DERUTF8String)value).getString().equals("This is a utf8 Â‰ˆ  Ístring"));
        
	}
	
	public void test08WrongEncoding() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERUTF8sdfTRING");
		props.put("id1.property.value", "This is a utf8 Â‰ˆ  Ístring");

		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		boolean exceptionThrown =false;
		try{	

			baseExt.getValue(null, null, null);
		}catch(CertificateExtentionConfigurationException e){
			exceptionThrown = true;
		}
		assertTrue(exceptionThrown);
	}
	
}
