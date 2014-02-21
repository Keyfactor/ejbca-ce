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
package org.cesecore.certificates.certificate.request;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Testing various aspects of request messages
 *
 * @version $Id$
 */
public class RequestMessageTest {

	 private static KeyPair keyPair;

	 @BeforeClass
	 public static void beforeClass() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		 CryptoProviderTools.installBCProviderIfNotAvailable();
		 keyPair = KeyTools.genKeys("512", null, "RSA");
	 }

	 @Test
	 public void test01Pkcs10RequestMessage() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, OperatorCreationException {
		 
	     PKCS10CertificationRequest basicpkcs10 = createP10("CN=Test,OU=foo");

		 PKCS10RequestMessage msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 String username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test,OU=foo", msg.getRequestDN());
		 assertEquals("dNSName=foo1.bar.com", msg.getRequestAltNames());

		 // Same message by try decoding byte array
		 msg = new PKCS10RequestMessage(basicpkcs10.getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test,OU=foo", msg.getRequestDN());
		 assertEquals("foo123", msg.getPassword());
		 
		 // Check public key
		 PublicKey pk = msg.getRequestPublicKey();
		 KeyTools.testKey(keyPair.getPrivate(), pk, "BC");
		 PKCS10RequestMessage msgempty = new PKCS10RequestMessage();
		 assertNull(msgempty.getRequestPublicKey());
		 
		 // Verify POP
		 assertTrue(msg.verify());
		 assertTrue(msg.verify(pk));
		 try {
			KeyPair otherkeys = KeyTools.genKeys("512", "RSA");
			assertFalse(msg.verify(otherkeys.getPublic()));
		} catch (InvalidAlgorithmParameterException e) {
			assertTrue("Should not throw", false);
		}
		 
		 // Try different DNs and DN oids
		 X500Name dn = new X500Name("C=SE, O=Foo, CN=Test Testsson");
		 basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

		 msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("C=SE,O=Foo,CN=Test Testsson", msg.getRequestDN());
		 assertEquals(null, msg.getRequestAltNames());
		 assertEquals(null, msg.getPassword());

		 dn = new X500Name("C=SE, O=Foo, CN=Test Testsson");
		 basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", dn, 
		         keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

		 msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("C=SE,O=Foo,CN=Test Testsson", msg.getRequestDN());
		 assertEquals(null, msg.getRequestAltNames());
		 assertEquals(null, msg.getPassword());

		 // oid for unstructuredName, will be handles specially by EJBCA
		 dn = new X500Name("CN=Test + 1.2.840.113549.1.9.2=AttrValue1");
		 basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

		 msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test,unstructuredName=AttrValue1", msg.getRequestDN());

		 dn = new X500Name("CN=Test + 1.2.840.113549.1.9.2=AttrValue1 AttrValue2");
		 basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

		 msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test,unstructuredName=AttrValue1 AttrValue2", msg.getRequestDN());

		 dn = new X500Name("CN=Test+1.2.840.113549.1.9.2=AttrValue1");
		 basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

		 msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test,unstructuredName=AttrValue1", msg.getRequestDN());

		 dn = new X500Name("CN=Test+1.2.840.113549.1.9.2=AttrValue1 AttrValue2");
		 basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

		 msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test,unstructuredName=AttrValue1 AttrValue2", msg.getRequestDN());

		 // Completely unknown oid
		 dn = new X500Name("CN=Test + 1.2.840.113549.1.9.3=AttrValue1");
		 basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

		 msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test+1.2.840.113549.1.9.3=AttrValue1", msg.getRequestDN());

		 dn = new X500Name("CN=Test + 1.2.840.113549.1.9.3=AttrValue1 AttrValue2");
		 basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

		 msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test+1.2.840.113549.1.9.3=AttrValue1 AttrValue2", msg.getRequestDN());

		 dn = new X500Name("CN=Test+1.2.840.113549.1.9.3=AttrValue1");
		 basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

		 msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test+1.2.840.113549.1.9.3=AttrValue1", msg.getRequestDN());

		 dn = new X500Name("CN=Test+1.2.840.113549.1.9.3=AttrValue1 AttrValue2");
		 basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

		 msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test+1.2.840.113549.1.9.3=AttrValue1 AttrValue2", msg.getRequestDN());

		 dn = new X500Name("1.2.840.113549.1.9.3=AttrValue1 AttrValue2+CN=Test");
		 basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

		 msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);

		 dn = new X500Name("1.2.840.113549.1.9.3=AttrValue1 AttrValue2+CN=Test+O=abc");
		 basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

		 msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);

		 dn = new X500Name("1.2.840.113549.1.9.3=AttrValue1\\+\\= AttrValue2+CN=Test+O=abc");	// very strange, but should still be valid 
		 basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);

		 msg = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);
	 }

    private PKCS10CertificationRequest createP10(final String subjectDN) throws IOException, OperatorCreationException {
        // Create a P10 with extensions, in this case altNames with a DNS name
		 ASN1EncodableVector altnameattr = new ASN1EncodableVector();
		 altnameattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
		 // AltNames
		 // String[] namearray = altnames.split(",");
		 GeneralNames san = CertTools.getGeneralNamesFromAltName("dNSName=foo1.bar.com");
		 ExtensionsGenerator extgen = new ExtensionsGenerator();
	     extgen.addExtension(Extension.subjectAlternativeName, false, san );
		 Extensions exts = extgen.generate();
		 altnameattr.add(new DERSet(exts));
		 
		 // Add a challenge password as well
		 ASN1EncodableVector pwdattr = new ASN1EncodableVector();
		 pwdattr.add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword); 
		 ASN1EncodableVector pwdvalues = new ASN1EncodableVector();
		 pwdvalues.add(new DERUTF8String("foo123"));
		 pwdattr.add(new DERSet(pwdvalues));
		 
		 // Complete the Attribute section of the request, the set (Attributes)
		 // contains one sequence (Attribute)
		 ASN1EncodableVector v = new ASN1EncodableVector();
		 v.add(new DERSequence(altnameattr));
		 v.add(new DERSequence(pwdattr));
		 DERSet attributes = new DERSet(v);

		 // Create the PKCS10
		 X500Name dn = new X500Name(subjectDN);
		 PKCS10CertificationRequest basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), attributes, keyPair.getPrivate(), null);
        return basicpkcs10;
    }
	 
    @Test
    public void testSNRepresentation () {
        SimpleRequestMessage req = new SimpleRequestMessage(keyPair.getPublic(), "dnorder", "foo123");
        req.setRequestDN("C=SE,O=Foo Company,SN=12345,SURNAME=surname,CN=DnOrderTest"); // This should not matter now
        X500Name reqname = req.getRequestX500Name();
        assertEquals("C=SE,O=Foo Company,SN=12345,SURNAME=surname,CN=DnOrderTest", reqname.toString());
    }

 }
