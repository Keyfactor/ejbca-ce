/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.xkms;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.SecretKey;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.log4j.Logger;
import org.apache.xml.security.utils.XMLUtils;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.core.protocol.xkms.common.XKMSUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.RSAKeyValueType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.PrivateKeyType;
import org.w3._2002._03.xkms_.PrototypeKeyBindingType;
import org.w3._2002._03.xkms_.RegisterRequestType;
import org.w3._2002._03.xkms_.RegisterResultType;
import org.w3._2002._03.xkms_.UseKeyWithType;
import org.w3c.dom.Document;

/**
 * 
 * 
 * 
 * @author Philip Vendil 2006 sep 27 
 *
 * @version $Id$
 */

public class XKMSEncTest {
	
	private static final Logger log = Logger.getLogger(XKMSEncTest.class);
		
	private ObjectFactory xKMSObjectFactory = new ObjectFactory();	
	private org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();
	
	private static JAXBContext jAXBContext = null;
	private static Marshaller marshaller = null;
	private static Unmarshaller unmarshaller = null;
	private static DocumentBuilderFactory dbf = null;

	
	@BeforeClass
	public static void beforeClass() {    	
		try {
			CryptoProviderTools.installBCProvider();
			org.apache.xml.security.Init.init();

			jAXBContext = JAXBContext.newInstance("org.w3._2002._03.xkms_:org.w3._2001._04.xmlenc_:org.w3._2000._09.xmldsig_");    		
			marshaller = XKMSUtil.getNamespacePrefixMappedMarshaller(jAXBContext);
			dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			unmarshaller = jAXBContext.createUnmarshaller();

		} catch (JAXBException e) {
			log.error("Error initializing RequestAbstractTypeResponseGenerator",e);
		}

	}

	@Before
    public void setUp() throws Exception {
    }

	@After
    public void tearDown() throws Exception {
    }
  
	@Test
    public void test01KeyEncryption() throws Exception {
        DocumentBuilder db = dbf.newDocumentBuilder();
        KeyPair keys = KeyTools.genKeys("1024", "RSA");                                
        RegisterResultType registerResultType = xKMSObjectFactory.createRegisterResultType();
        JAXBElement<RegisterResultType> registerResult = xKMSObjectFactory.createRegisterResult(registerResultType);
                
        PrivateKeyType privateKeyType1 = XKMSUtil.getEncryptedXMLFromPrivateKey( (RSAPrivateCrtKey) keys.getPrivate(), "This is total crap");
        registerResultType.setPrivateKey(privateKeyType1);
        
        Document registerResultDoc = db.newDocument();
        marshaller.marshal( registerResult, registerResultDoc );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLUtils.outputDOM(registerResultDoc, baos);
        log.debug("XMLUtils.outputDOM: " + baos.toString());
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

        @SuppressWarnings("unchecked")
        JAXBElement<RegisterResultType> registerResult2 = (JAXBElement<RegisterResultType>) unmarshaller.unmarshal(bais);
        registerResultType = registerResult2.getValue();
        
        PrivateKeyType privateKeyType2 = registerResultType.getPrivateKey();
        RSAPrivateKey privkey2 = XKMSUtil.getPrivateKeyFromEncryptedXML(privateKeyType2, "This is total crap");
        X509Certificate cert = CertTools.genSelfCert("CN=test", 10, null,privkey2, keys.getPublic(), "SHA1WithRSA", true);
        cert.verify(keys.getPublic());    
    }    
	
	@Test
	public void test02TestAliceRegistrationAuthenticationKey() throws Exception{	
		String authenticationData= "024837";
		
        SecretKey retval = XKMSUtil.getSecretKeyFromPassphrase(authenticationData, true, 20, XKMSUtil.KEY_AUTHENTICATION);
				
		assertTrue(retval.getEncoded().length == 20);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Hex.encode(retval.getEncoded(), baos);
		
		String resultString = new String(baos.toByteArray());
		assertTrue(resultString.equalsIgnoreCase("d6cc34cb83fae2993a393aa8e7de9a06c7fa2c92"));
	}
	

	
	@Test
	public void test03TestBOBRegistrationPrivateKeyEncryption() throws Exception{
		
		String authenticationData= "3N9CJ-K4JKS-04JWF-0934J-SR09JW-IK4";
		
        SecretKey retval = XKMSUtil.getSecretKeyFromPassphrase(authenticationData, true, 24, XKMSUtil.KEY_PRIVATEKEYDATA);
		
		assertTrue(retval.getEncoded().length == 24);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Hex.encode(retval.getEncoded(), baos);
				
		String resultString = new String(baos.toByteArray());
		log.debug(resultString);
		assertTrue(resultString.equalsIgnoreCase("78e8bbf532d01dece38aa9d2a4a409dbff1a265cdbae1b95"));

	}
	
	@Test
	public void test04TestRevocationCodeIdentifyerGeneration() throws Exception{
		String authenticationData= "Help I Have Revealed My Key";
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Hex.encode(authenticationData.getBytes(), baos);
				
		String resultString = new String(baos.toByteArray());
		log.debug(resultString);
		assertTrue(resultString.equalsIgnoreCase("48656c70204920486176652052657665616c6564204d79204b6579"));
		
        SecretKey key1 = XKMSUtil.getSecretKeyFromPassphrase(authenticationData, true, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1);
		
		assertTrue(key1.getEncoded().length == 20);
		
		baos = new ByteArrayOutputStream();
		Hex.encode(key1.getEncoded(), baos);
				
		resultString = new String(baos.toByteArray());
		log.debug(resultString);
		assertTrue(resultString.equalsIgnoreCase("1c0857c95458c26f44327efd0ef055b08cad5c78"));
		
	    SecretKey key2 = XKMSUtil.getSecretKeyFromPassphrase(new String(key1.getEncoded(),"ISO8859-1"), false,20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS2);
			
	    assertTrue(key2.getEncoded().length == 20);
			
	    baos = new ByteArrayOutputStream();
	    Hex.encode(key2.getEncoded(), baos);

	    resultString = new String(baos.toByteArray());
	    log.debug(resultString);
	    assertTrue(resultString.equalsIgnoreCase("e6b44dd9c39988c95c889c41a9a7a5ad90c2cd21"));
        
	    String byte64String = new String(Base64.encode(key2.getEncoded(), false));
	    log.debug(byte64String);
	    assertTrue(byte64String.equals("5rRN2cOZiMlciJxBqaelrZDCzSE="));
	}
	
	@Test
	public void test04TestPublicKeyExtraction() throws Exception{
        DocumentBuilder db = dbf.newDocumentBuilder();
        KeyPair keys = KeyTools.genKeys("1024", "RSA");    
        
    	RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
    	registerRequestType.setId("523");       	
        	
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier("CN=Test Testarsson");
        
        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
    	
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keys.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keys.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);                
        JAXBElement<RegisterRequestType> registerRequest = xKMSObjectFactory.createRegisterRequest(registerRequestType);

        Document registerRequestDoc = db.newDocument();
        marshaller.marshal( registerRequest, registerRequestDoc );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLUtils.outputDOM(registerRequestDoc, baos);
        log.debug("XMLUtils.outputDOM: " + baos.toString());
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

        @SuppressWarnings("unchecked")
        JAXBElement<RegisterRequestType> registerRequest2 = (JAXBElement<RegisterRequestType>) unmarshaller.unmarshal(bais);
        registerRequestType = registerRequest2.getValue();
        
        @SuppressWarnings("unchecked")
        RSAKeyValueType rSAKeyValueType  = (RSAKeyValueType) ((JAXBElement<RSAKeyValueType>) registerRequestType.getPrototypeKeyBinding().getKeyInfo().getContent().get(0)).getValue();        
        RSAPublicKeySpec rSAPublicKeySpec = new RSAPublicKeySpec(new BigInteger(rSAKeyValueType.getModulus()), new BigInteger(rSAKeyValueType.getExponent()));        
        RSAPublicKey rSAPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(rSAPublicKeySpec);
        
        X509Certificate cert = CertTools.genSelfCert("CN=test", 10, null,keys.getPrivate(), rSAPublicKey, "SHA1WithRSA", true);
        
        cert.verify(rSAPublicKey);  
	}
}
