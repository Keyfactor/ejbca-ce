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
package org.ejbca.core.protocol;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import junit.framework.TestCase;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Testing various aspects of request messages
 *
 * @version $Id$
 */public class RequestMessageTest extends TestCase {

	 private final KeyPair keyPair;

	 public RequestMessageTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		 CryptoProviderTools.installBCProvider();
		 keyPair = KeyTools.genKeys("512", null, "RSA");
	 }

	 public void test01Pkcs10RequestMessage() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		 X509Name dn = new X509Name("CN=Test,OU=foo");
		 PKCS10CertificationRequest basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 PKCS10RequestMessage msg = new PKCS10RequestMessage(basicpkcs10);
		 String username = msg.getUsername();
		 assertEquals("Test", username);

		 dn = new X509Name("C=SE, O=Foo, CN=Test Testsson");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);

		 // oid for unstructuredName, will be handles specially by EJBCA
		 dn = new X509Name("CN=Test + 1.2.840.113549.1.9.2=AttrValue1");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);

		 dn = new X509Name("CN=Test + 1.2.840.113549.1.9.2=AttrValue1 AttrValue2");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);

		 dn = new X509Name("CN=Test+1.2.840.113549.1.9.2=AttrValue1");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);

		 dn = new X509Name("CN=Test+1.2.840.113549.1.9.2=AttrValue1 AttrValue2");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);

		 // Completely unknown oid
		 dn = new X509Name("CN=Test + 1.2.840.113549.1.9.3=AttrValue1");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);

		 dn = new X509Name("CN=Test + 1.2.840.113549.1.9.3=AttrValue1 AttrValue2");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);

		 dn = new X509Name("CN=Test+1.2.840.113549.1.9.3=AttrValue1");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);

		 dn = new X509Name("CN=Test+1.2.840.113549.1.9.3=AttrValue1 AttrValue2");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);

	 }
 }
