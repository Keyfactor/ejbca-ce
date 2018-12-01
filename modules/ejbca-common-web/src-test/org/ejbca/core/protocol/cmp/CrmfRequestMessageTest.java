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

package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.ra.UsernameGenerator;
import org.ejbca.core.model.ra.UsernameGeneratorParams;
import org.junit.Before;
import org.junit.Test;

/**
 * Test to verify that CrmfRequestMessage can be properly Serialized.
 * Previously the fields in the inherited class BaseCmpMessage could not be properly Serialized.
 * 
 * @version $Id$
 */
public class CrmfRequestMessageTest {

	@Before
    public void setUp() throws Exception {
    	CryptoProviderTools.installBCProviderIfNotAvailable();
    }

	@Test
    public void testCrmfRequestMessageSerialization() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        // Create a bogus PKIMessage
    	PKIMessage myPKIMessage = createPKIMessage("CN=bogusIssuer", "CN=bogusSubject");
        
    	// Create a bogus CrmfRequestMessage
    	CrmfRequestMessage crmf = new CrmfRequestMessage(myPKIMessage, "CN=SomeCA", true, null);
    	crmf.setPbeParameters("keyId", "key", "digestAlg", "macAlg", 100);
    	// Serialize it
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	ObjectOutputStream oos = new ObjectOutputStream(baos);
    	oos.writeObject(crmf);
    	// Deserialize it
    	ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()));
    	Object o = ois.readObject();
    	assertTrue("The deserialized object was not of type CrmfRequestMessage.", o instanceof CrmfRequestMessage);
    	CrmfRequestMessage crmf2 = (CrmfRequestMessage) o;
    	assertEquals("Inherited object was not properly deserilized: ", "macAlg", crmf2.getPbeMacAlg());
    }

	@Test
	public void testCrmfRequestUsernameGeneratorFromDN() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
	    CryptoProviderTools.installBCProviderIfNotAvailable();
	    {
	        final PKIMessage myPKIMessage = createPKIMessage("CN=bogusIssuer", "CN=subject,SN=000106716,O=Org,C=SE");
	        final CrmfRequestMessage crmf = new CrmfRequestMessage(myPKIMessage, "CN=SomeCA", true, null);
	        final X500Name dnname = crmf.getRequestX500Name();
	        final UsernameGeneratorParams params = new UsernameGeneratorParams();
	        params.setMode(UsernameGeneratorParams.DN);
	        UsernameGenerator gen = UsernameGenerator.getInstance(params);
	        String username = gen.generateUsername(dnname.toString());
	        assertEquals("Username was not constructed properly from DN (CN)", "subject", username);
	        params.setDNGeneratorComponent("");
	        gen = UsernameGenerator.getInstance(params);
	        username = gen.generateUsername(dnname.toString());
	        assertEquals("Username was not constructed properly from DN", "CN=subject,SN=000106716,O=Org,C=SE", username);
	    }
	    {
	        // DN order the other way around, should give username the other way around as well
	        final PKIMessage myPKIMessage = createPKIMessage("CN=bogusIssuer", "C=SE,O=Org,SERIALNUMBER=000106716,CN=subject");
	        final CrmfRequestMessage crmf = new CrmfRequestMessage(myPKIMessage, "CN=SomeCA", true, null);
	        final X500Name dnname = crmf.getRequestX500Name();
	        final UsernameGeneratorParams params = new UsernameGeneratorParams();
	        params.setMode(UsernameGeneratorParams.DN);
	        UsernameGenerator gen = UsernameGenerator.getInstance(params);
	        String username = gen.generateUsername(dnname.toString());
	        assertEquals("Username was not constructed properly from DN (CN)", "subject", username);
	        params.setDNGeneratorComponent("");
	        gen = UsernameGenerator.getInstance(params);
	        username = gen.generateUsername(dnname.toString());
	        assertEquals("Username was not constructed properly from DN", "C=SE,O=Org,SN=000106716,CN=subject", username);
	    }
	}

    private PKIMessage createPKIMessage(final String issuerDN, final String subjectDN) throws InvalidAlgorithmParameterException, IOException {
		KeyPair keys = KeyTools.genKeys("1024", "RSA");
		ASN1EncodableVector optionalValidityV = new ASN1EncodableVector();
		org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
		org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
		optionalValidityV.add(new DERTaggedObject(true, 0, nb));
		optionalValidityV.add(new DERTaggedObject(true, 1, na));
		OptionalValidity myOptionalValidity = OptionalValidity.getInstance(new DERSequence(optionalValidityV));
		
		CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();
		myCertTemplate.setValidity( myOptionalValidity );
		myCertTemplate.setIssuer(new X500Name(issuerDN));
        myCertTemplate.setSubject(new X500Name(subjectDN));
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());
        myCertTemplate.setPublicKey(keyInfo);    
		ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
		DEROutputStream         dOut = new DEROutputStream(bOut);
		ExtensionsGenerator extgen = new ExtensionsGenerator();
		int bcku = X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment | X509KeyUsage.nonRepudiation;
		X509KeyUsage ku = new X509KeyUsage(bcku);
		bOut = new ByteArrayOutputStream();
		dOut = new DEROutputStream(bOut);
		dOut.writeObject(ku);
		byte[] value = bOut.toByteArray();
		extgen.addExtension(Extension.keyUsage, false, new DEROctetString(value));
		myCertTemplate.setExtensions(extgen.generate());
		        
		CertRequest myCertRequest = new CertRequest(4, myCertTemplate.build(), null);
		        
		ProofOfPossession myProofOfPossession = new ProofOfPossession();
		AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String("foo123"));
		AttributeTypeAndValue[] avs = {av};
		CertReqMsg myCertReqMsg = new CertReqMsg(myCertRequest, myProofOfPossession, avs);
        CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);
        
        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(new X500Name("CN=bogusSubject")), new GeneralName(new X500Name("CN=bogusIssuer")));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        myPKIHeader.setSenderNonce(new DEROctetString(CmpMessageHelper.createSenderNonce()));
        myPKIHeader.setTransactionID(new DEROctetString(CmpMessageHelper.createSenderNonce()));

        PKIBody myPKIBody = new PKIBody(0, myCertReqMessages);
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        return myPKIMessage;
    }

	@Test
    public void testNovosecRARequest()
            throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            CertificateEncodingException, SignatureException, IllegalStateException, InvalidCmpProtectionException {
    	// Check that we can parse a request from  Novosec (patched by EJBCA).
    	// Read an initialization request with RAVerifiedPOP and PBE protection to see that we can process it
        ASN1InputStream in = new ASN1InputStream(novosecrapopir);
        try {
            ASN1Primitive derObject = in.readObject();
            PKIMessage req = PKIMessage.getInstance(derObject);
            //log.info(req.toString());
            // Verify should be false if we do not allow RA verify POP here, since we don't have any normal POP
            CrmfRequestMessage msg = new CrmfRequestMessage(req, "CN=AdminCA1", false, "CN");
            assertFalse(msg.verify());
            // Verify should be ok when we allow RA verified POP
            msg = new CrmfRequestMessage(req, "CN=AdminCA1", true, "CN");
            assertTrue(msg.verify());
            assertEquals("CN=AdminCA1,O=EJBCA Sample,C=SE", msg.getIssuerDN());
            assertEquals("CN=abc123rry-4371939543913639881,O=PrimeKey Solutions AB,C=SE", msg.getRequestDN());
            assertEquals("abc123rry-4371939543913639881", msg.getUsername());
            assertEquals("foo123", msg.getPassword());
            // Verify PBE protection
            PKIHeader head = msg.getHeader();
            final ASN1OctetString os = head.getSenderKID();
            String keyId = CmpMessageHelper.getStringFromOctets(os);
            assertEquals("mykeyid", keyId);
            final CmpPbeVerifyer verifyer = new CmpPbeVerifyer(msg.getMessage());
            assertTrue(verifyer.verify("foo123"));
            assertFalse(verifyer.verify("bar123"));
        } finally {
            in.close();
        }
    }

	@Test
	public void testNovosecClientRequestSHA1() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, IllegalStateException, OperatorCreationException, CertificateException {
	    doNovosecClientRequest("SHA1WithRSA", CMSSignedGenerator.DIGEST_SHA1, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
	}
    @Test
    public void testNovosecClientRequestSHA256() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, IllegalStateException, OperatorCreationException, CertificateException {
        doNovosecClientRequest("SHA256WithRSA", CMSSignedGenerator.DIGEST_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId());
    }

    private void doNovosecClientRequest(final String sigAlg, final String digestAlg, final String expectedAlgOid) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, IllegalStateException, OperatorCreationException, CertificateException {
    	// Check that we can parse a request from  Novosec (patched by EJBCA).
    	// Read an initialization request with a signature POP and signature protection to see that we can process it
    	{
    		ASN1InputStream in = new ASN1InputStream(novosecsigpopir);
    		try {
    		ASN1Primitive derObject = in.readObject();
    		PKIMessage req = PKIMessage.getInstance(derObject);
    		//log.info(req.toString());
    		// Verify should be ok if we do not allow RA verify POP here
    		CrmfRequestMessage msg = new CrmfRequestMessage(req, "CN=AdminCA1", false, "CN");
    		assertTrue(msg.verify());
    		// Since we don't have RA POP we can't test for that...
    		assertEquals("CN=AdminCA1,O=EJBCA Sample,C=SE", msg.getIssuerDN());
    		assertEquals("CN=abc123rry2942812801980668853,O=PrimeKey Solutions AB,C=SE", msg.getRequestDN());
    		assertEquals("abc123rry2942812801980668853", msg.getUsername());
    		assertEquals("foo123", msg.getPassword());
    		// Verify signature protection
    		AlgorithmIdentifier algId = msg.getMessage().getHeader().getProtectionAlg();
    		String oid = algId.getAlgorithm().getId();
    		assertEquals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), oid);
    		// Check that this is an old message, created before ECA-2104, using null instead of DERNull as algorithm parameters.
    		ASN1Encodable pp = algId.getParameters();
    		assertNull(pp);
    		// Try to verify, it should work good even though the small bug in ECA-2104, since we don't use algorithm parameters for RSA-PKCS signatures
    		PublicKey pubKey = msg.getRequestPublicKey();
    		assertTrue(CmpMessageHelper.verifyCertBasedPKIProtection(msg.getMessage(), pubKey));
    		// Verify that our verification routine does not give positive result for any other keys
    		KeyPair keys = KeyTools.genKeys("512", "RSA");
    		assertFalse(CmpMessageHelper.verifyCertBasedPKIProtection(msg.getMessage(), keys.getPublic()));
    		} finally {
    		    in.close();
    		}
    	}
    	// Re-protect the message, now fixed by ECA-2104
    	{
    		ASN1InputStream in = new ASN1InputStream(novosecsigpopir);
    		try {
    		ASN1Primitive derObject = in.readObject();
    		PKIMessage myPKIMessage = PKIMessage.getInstance(derObject);
    		KeyPair keys = KeyTools.genKeys("512", "RSA");
    		X509Certificate signCert = CertTools.genSelfCert("CN=CMP Sign Test", 3650, null, keys.getPrivate(), keys.getPublic(), sigAlg, false);
    		// Re-sign the message
    		Collection<Certificate> signCertChain = new ArrayList<Certificate>();
    		signCertChain.add(signCert);
    		byte[] newmsg = CmpMessageHelper.signPKIMessage(myPKIMessage, signCertChain, keys.getPrivate(), digestAlg, "BC");
    		in.close();
    		in = new ASN1InputStream(newmsg);		
    		derObject = in.readObject();
    		PKIMessage pkimsg = PKIMessage.getInstance(derObject);
    		// We have to do this twice, because Novosec caches ProtectedBytes in the PKIMessage object, so we need to 
    		// encode it and re-decode it again to get the changes from ECA-2104 encoded correctly.
    		// Not needed when simply signing a new message that you create, only when re-signing 
    		newmsg = CmpMessageHelper.signPKIMessage(pkimsg, signCertChain, keys.getPrivate(), digestAlg, "BC");
    		in.close();
    		in = new ASN1InputStream(newmsg);
    		derObject = in.readObject();
    		pkimsg = PKIMessage.getInstance(derObject);
    		AlgorithmIdentifier algId = pkimsg.getHeader().getProtectionAlg();
    		String oid = algId.getAlgorithm().getId();
    		assertEquals(expectedAlgOid, oid);
    		// Check that we have DERNull and not plain java null as algorithm parameters.
    		ASN1Encodable pp = algId.getParameters();
    		assertNotNull(pp);
    		assertEquals(DERNull.class.getName(), pp.getClass().getName());
    		// Try to verify, also verify at the same time that encoding decoding of the signature works
    		assertTrue(CmpMessageHelper.verifyCertBasedPKIProtection(pkimsg, keys.getPublic()));
    		// Verify that our verification routine does not give positive result for any other keys
    		CrmfRequestMessage msg = new CrmfRequestMessage(pkimsg, "CN=AdminCA1", false, "CN");
    		assertTrue(msg.verify());
    		PublicKey pubKey = msg.getRequestPublicKey();
    		assertFalse(CmpMessageHelper.verifyCertBasedPKIProtection(pkimsg, pubKey));
    		} finally {
    		    in.close();
    		}
    	}
    }

	@Test
    public void testBc146RARequest() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidCmpProtectionException {
    	internalBcRARequestTest(bc146rapopir);
    }

	@Test
    public void testBc147RARequest() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException,
            InvalidCmpProtectionException {
    	internalBcRARequestTest(bc147rapopir);
    }

    private void internalBcRARequestTest(byte[] message) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException, InvalidCmpProtectionException {
    	// Check that we can parse request from BouncyCastle version 1.46.
    	// Read an initialization request with RAVerifiedPOP with PBE protection to see that we can process it
    	ASN1InputStream in = new ASN1InputStream(message);
        try {
            ASN1Primitive derObject = in.readObject();
            PKIMessage req = PKIMessage.getInstance(derObject);
            //log.info(req.toString());
            // Verify should be false if we do not allow RA verify POP here, since we don't have any normal POP
            CrmfRequestMessage msg = new CrmfRequestMessage(req, "CN=AdminCA1", false, "CN");
            assertFalse(msg.verify());
            // Verify should be ok when we allow RA verified POP
            msg = new CrmfRequestMessage(req, "CN=AdminCA1", true, "CN");
            assertTrue(msg.verify());
            assertEquals("CN=AdminCA1", msg.getIssuerDN());
            assertEquals("CN=user", msg.getRequestDN());
            assertEquals("user", msg.getUsername());
            // We should want a password
            assertEquals("foo123", msg.getPassword());
            // Verify PBE protection
            PKIHeader head = msg.getHeader();
            final ASN1OctetString os = head.getSenderKID();
            String keyId = CmpMessageHelper.getStringFromOctets(os);
            assertEquals(CmpConfiguration.PROFILE_USE_KEYID, keyId);
            final CmpPbeVerifyer verifyer = new CmpPbeVerifyer(msg.getMessage());
            assertTrue(verifyer.verify("password"));
            assertFalse(verifyer.verify("foo123"));
        } finally {
            in.close();
        }
    }

    @Test
    public void testBc146ClientRequest() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    	internalBcClientRequestTest(bc146sigpopir);
    }
    
    @Test
    public void testBc147ClientRequest() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    	internalBcClientRequestTest(bc147sigpopir);
    }

    private void internalBcClientRequestTest(byte[] message) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    	// Check that we can parse request from BouncyCastle version 1.46.    	
    	// Read an initialization request with a signature POP, and signature protection, to see that we can process it
    	ASN1InputStream in = new ASN1InputStream(message);
        try {
            ASN1Primitive derObject = in.readObject();
            PKIMessage req = PKIMessage.getInstance(derObject);
            //log.info(req.toString());
            // Verify should be ok if we do not allow RA verify POP here
            CrmfRequestMessage msg = new CrmfRequestMessage(req, "CN=AdminCA1", false, "CN");
            // BC messages in BC1.46 uses POPOSigningKeyInput for POPO, not the 3rd case in RFC4211 section 4.1, like everyone else...
            // BC messages in BC1.47 should use normal POPO, 3rd case
            assertTrue(msg.verify());
            // Since we don't have RA POP we can't test for that...
            assertEquals("CN=AdminCA1", msg.getIssuerDN());
            assertEquals("CN=user", msg.getRequestDN());
            assertEquals("user", msg.getUsername());
            assertEquals("foo123", msg.getPassword());
            // Check signature protection
            AlgorithmIdentifier algId = msg.getMessage().getHeader().getProtectionAlg();
            String oid = algId.getAlgorithm().getId();
            assertEquals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), oid);
            // Check that we have DERNull and not plain java null as algorithm parameters.
            ASN1Encodable pp = algId.getParameters();
            assertNotNull(pp);
            assertEquals(DERNull.class.getName(), pp.getClass().getName());
            // Try to verify the protection signature
            assertTrue(CmpMessageHelper.verifyCertBasedPKIProtection(msg.getMessage(), msg.getRequestPublicKey()));
        } finally {
            in.close();
        }
    }

    @Test
    public void testHuaweiEnodeBClientRequest() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        // Read an initialization request to see that we can process it
        ASN1InputStream in = new ASN1InputStream(huaweiir);
        try {
            ASN1Primitive derObject = in.readObject();
            PKIMessage req = PKIMessage.getInstance(derObject);
            //log.info(req.toString());
            CrmfRequestMessage msg = new CrmfRequestMessage(req, null, false, "CN");
            // This message does not have an issuerDN in the cert template
            assertNull(msg.getIssuerDN());
            // Use a default CA instead
            msg = new CrmfRequestMessage(req, "CN=AdminCA1", false, "CN");
            assertTrue(msg.verify());
            assertEquals("CN=AdminCA1", msg.getIssuerDN());
            assertEquals("CN=21030533610000000012 eNodeB", msg.getRequestDN());
            assertEquals("21030533610000000012 eNodeB", msg.getUsername());
            // We would like a password here...
            assertNull(msg.getPassword());
            AlgorithmIdentifier algId = msg.getMessage().getHeader().getProtectionAlg();
            String oid = algId.getAlgorithm().getId();
            assertEquals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), oid);
            // Check that we have DERNull and not plain java null as algorithm parameters.
            ASN1Encodable pp = algId.getParameters();
            assertNotNull(pp);
            assertEquals(DERNull.class.getName(), pp.getClass().getName());
            // Get the public key from the request
            PublicKey pubKey = msg.getRequestPublicKey();
            assertNotNull("We should have a public key in the request", pubKey);
            // Try to verify message protection
            // Does not work for this Huawei message, is it signed by the same key as in the request at all?
            // We will wait for another huawei message to test
            //assertTrue(CmpMessageHelper.verifyCertBasedPKIProtection(msg.getMessage(), pubKey));

            // Read the CertConf (certificate confirmation) CMP message that the client sends to
            // the CA after receiving the certificate. RFC4210 section "5.3.18.  Certificate Confirmation Content".
            in.close();
            in = new ASN1InputStream(huaweicertconf);
            derObject = in.readObject();
            PKIMessage certconf = PKIMessage.getInstance(derObject);
            //log.info(certconf.toString());
            GeneralCmpMessage conf = new GeneralCmpMessage(certconf);
            algId = conf.getMessage().getHeader().getProtectionAlg();
            oid = algId.getAlgorithm().getId();
            assertEquals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), oid);
            // Check that we have DERNull and not plain java null as algorithm parameters.
            pp = algId.getParameters();
            assertNotNull(pp);
            assertEquals(DERNull.class.getName(), pp.getClass().getName());
            // Try to verify message protection
            // Does not work for this Huawei message, is it signed by the same key as in the request at all?
            // We will wait for another huawei message to test
            //assertTrue(CmpMessageHelper.verifyCertBasedPKIProtection(msg.getMessage(), pubKey));
        } finally {
            in.close();
        }
    }

    @Test
    public void testBlueXIR() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        // Read an initialization request to see that we can process it
        ASN1InputStream in = new ASN1InputStream(bluexir);
        try {
            ASN1Primitive derObject = in.readObject();
            PKIMessage req = PKIMessage.getInstance(derObject);
            //log.info(req.toString());
            CrmfRequestMessage msg = new CrmfRequestMessage(req, null, false, "CN");
            // This message does not have an issuerDN in the cert template
            assertNull(msg.getIssuerDN());
            // Use a default CA instead
            msg = new CrmfRequestMessage(req, "CN=AdminCA1", false, "CN");
            // Verifying POP does not work on this very old BlueX request, check that it fails
            assertFalse(msg.verify());
            assertEquals("CN=AdminCA1", msg.getIssuerDN());
            assertEquals("CN=Some Common Name", msg.getRequestDN());
            assertEquals("Some Common Name", msg.getUsername());
            // We would like a password here...
            assertNull(msg.getPassword());
            AlgorithmIdentifier algId = msg.getMessage().getHeader().getProtectionAlg();
            String oid = algId.getAlgorithm().getId();
            assertEquals("1.2.840.113533.7.66.13", oid); // HMAC password based protection
            // Get the public key from the request, this does not work either on this message, there is something wrong with the public key
            try {
                msg.getRequestPublicKey();
                fail("We expect public key to be invalid in this very old BlueX message");
            } catch (InvalidKeyException e) {
                assertEquals("The message should be that the public key is", "Error decoding public key.", e.getMessage());
            }
        } finally {
            in.close();
        }
    }

    static byte[] bluexir = Base64.decode(("MIICIjCB1AIBAqQCMACkVjBUMQswCQYDVQQGEwJOTDEbMBkGA1UEChMSQS5FLlQu"
            + "IEV1cm9wZSBCLlYuMRQwEgYDVQQLEwtEZXZlbG9wbWVudDESMBAGA1UEAxMJVGVz" + "dCBDQSAxoT4wPAYJKoZIhvZ9B0INMC8EEAK/H7Do+55N724Kdvxm7NcwCQYFKw4D"
            + "AhoFAAICA+gwDAYIKwYBBQUIAQIFAKILBAlzc2xjbGllbnSkEgQQpFpBsonfhnW8" + "ia1otGchraUSBBAyzd3nkKAzcJqGFrDw0jkYoIIBLjCCASowggEmMIIBIAIBADCC"
            + "ARmkJqARGA8yMDA2MDkxOTE2MTEyNlqhERgPMjAwOTA2MTUxNjExMjZapR0wGzEZ" + "MBcGA1UEAwwQU29tZSBDb21tb24gTmFtZaaBoDANBgkqhkiG9w0BAQEFAAOBjgAw"
            + "gYoCgYEAuBgTGPgXrS3AIPN6iXO6LNf5GzAcb/WZhvebXMdxdrMo9+5hw/Le5St/" + "Sz4J93rxU95b2LMuHTg8U6njxC2lZarNExZTdEwnI37X6ep7lq1purq80zD9bFXj"
            + "ougRD5MHfhDUAQC+btOgEXkanoAo8St3cbtHoYUacAXN2Zs/RVcCBAABAAGpLTAr" + "BgNVHREEJDAioCAGCisGAQQBgjcUAgOgEgwQdXBuQGFldGV1cm9wZS5ubIAAoBcD"
            + "FQAy/vSoNUevcdUxXkCQx3fvxkjh6A==").getBytes());

    /** CMP initial request message, created with Huawei eNode B, with signature POP (no POPOSigningKey) and signature protection */
    static byte[] huaweiir = Base64.decode(("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" +
    		"OZck9LLi").getBytes());

    /** CMP Cert Confirmation message, created with Huawei eNode B, with signature POP (no POPOSigningKey) and signature protection */
    static byte[] huaweicertconf = Base64.decode(("MIIBrTCB/gIBAqRuMGwxCzAJBgNVBAYTAkNOMQ8wDQYDVQQKEwZIdWF3ZWkxJjAkBgNVBAsTHVdp" +
    		"cmVsZXNzIE5ldHdvcmsgUHJvZHVjdCBMaW5lMSQwIgYDVQQDExsyMTAzMDUzMzYxMDAwMDAwMDAx" +
    		"MiBlTm9kZUKkVDBSMQswCQYDVQQGEwJjbjELMAkGA1UECBMCc2gxCzAJBgNVBAcTAnFjMQswCQYD" +
    		"VQQKEwJ3bDEMMAoGA1UECxMDbHRlMQ4wDAYDVQQDEwVlbmJjYaEPMA0GCSqGSIb3DQEBBQUApAYE" +
    		"BEbnKIilBgQEWWI60aYSBBATrD26fYGHOwYhgJaiquBEuCMwITAfBBR5s9gPoXPyWm2uEGhrPssR" +
    		"QIhf0AICAWMwAwIBAKCBhAOBgQBmn2VJ+0olRYdN7W2sX0cyVjYGPLcla5Nb6f9BDoYiKMhwnFmk" +
    		"QUGpsIklj0MibFx8qN1Nz5IiYOgMmEDc5P++v/hwYQs9P1/j+8jQEtSYYxEP/w3sX56bhIQAw+37" +
    		"Um6i30qhLj/1YtCx/5guQwG+Fu4tcsE6dI98R23Pd5dbWg==").getBytes());

    /** CMP Cert Response message, sent to Huawei eNode B
     * Not used, just kept for reference */
    static byte[] huaweiresponse = Base64.decode(("MIILtTCCARECAQKkVDBSMQswCQYDVQQGEwJjbjELMAkGA1UECBMCc2gxCzAJBgNVBAcTAnFjMQsw" +
    		"CQYDVQQKEwJ3bDEMMAoGA1UECxMDbHRlMQ4wDAYDVQQDEwVlbmJjYaRuMGwxCzAJBgNVBAYTAkNO" +
    		"MQ8wDQYDVQQKEwZIdWF3ZWkxJjAkBgNVBAsTHVdpcmVsZXNzIE5ldHdvcmsgUHJvZHVjdCBMaW5l" +
    		"MSQwIgYDVQQDExsyMTAzMDUzMzYxMDAwMDAwMDAxMiBlTm9kZUKgERgPMjAxMTAyMjIxNzU2MDFa" +
    		"oQ8wDQYJKoZIhvcNAQEFBQCkBgQERucoiKUSBBATrD26fYGHOwYhgJaiquBEpgYEBCGfBFKhggVD" +
    		"MIIFP6GCAmgwggJkMIICYDCCAcmgAwIBAgIJALJSzpNbH+s6MA0GCSqGSIb3DQEBBQUAMFQxCzAJ" +
    		"BgNVBAYTAmNuMQswCQYDVQQIEwJzaDELMAkGA1UEBxMCcWMxCzAJBgNVBAoTAndsMQwwCgYDVQQL" +
    		"EwNsdGUxEDAOBgNVBAMTB2VuYnJvb3QwHhcNMTAwNjAzMDgzMzI4WhcNMTEwNjAzMDgzMzI4WjBS" +
    		"MQswCQYDVQQGEwJjbjELMAkGA1UECBMCc2gxCzAJBgNVBAcTAnFjMQswCQYDVQQKEwJ3bDEMMAoG" +
    		"A1UECxMDbHRlMQ4wDAYDVQQDEwVlbmJjYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzIwN" +
    		"8oP7/TcXeFpDmXZZlKkeZ4/PAzRancAj6mmdhbeZY+lvgOt/KmQyolu1jPkUUDDy2nxzyuuADAQe" +
    		"C9o6VHgteppQzT2XC75ol5YUc1BtCaU2CD7MmpqFC9NB/UWCP++r1mRPXWzdI/rkhAqudfberNRX" +
    		"ouSmmHXqF0KQY+UCAwEAAaM8MDowHQYDVR0OBBYEFExg23UkAFE/LF9llJj7VRVeIwBFMAwGA1Ud" +
    		"EwQFMAMBAf8wCwYDVR0PBAQDAgH2MA0GCSqGSIb3DQEBBQUAA4GBACppwv0KgJOD6st8oW5IyKuz" +
    		"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").getBytes());

    
    /** CMP initial request message, created with BouncyCastle 1.46, with RAVerified POP and PBE protection */
    static byte[] bc146rapopir = Base64.decode(("MIIBcjCBowIBAqQRMA8xDTALBgNVBAMMBHVzZXKkFTATMREwDwYDVQQDDAhBZG1pbkNBMaARGA8yMDExMDUzMDA5MjUxMlqhQDA+BgkqhkiG9n0HQg0wMQQU5CQjYqE1xefkRkpUs+gnZvbik88wBwYFKw4DAhoCAgPoMAwGCCsGAQUFCAECBQCiBwQFS2V5SWSkCgQI9oHh9MJNp/qlCgQI9oHh9MJNp/qggbAwga0wgaowgaUCAXswgYijFTATMREwDwYDVQQDDAhBZG1pbkNBMaURMA8xDTALBgNVBAMMBHVzZXKmXDANBgkqhkiG9w0BAQEFAANLADBIAkEAzPE7ZaY6jiyeELeotH4rHA3imjvDwrzgcrefX3gbNiOKiz9/CJwQOU/V2jCc8pbAm02TS41ZSwrL7B7v4rtWbQIDAQABMBUwEwYJKwYBBQUHBQEBDAZmb28xMjOAAKAXAxUA49wkvBjdn5ENdJJnJb3wU1bHmcs=").getBytes());
    
    /** CMP initial request message, created with BouncyCastle 1.46, with POPOSigningKey POP and signature protection */
    static byte[] bc146sigpopir = Base64.decode(("MIICNzByAgECpBEwDzENMAsGA1UEAwwEdXNlcqQVMBMxETAPBgNVBAMMCEFkbWluQ0ExoBEYDzIwMTEwNTMwMTQxNTQ2WqEPMA0GCSqGSIb3DQEBBQUAogcEBUtleUlkpAoECBJ7Wyn/3xaopQoECBJ7Wyn/3xaooIIBejCCAXYwggFyMIGlAgF7MIGIoxUwEzERMA8GA1UEAwwIQWRtaW5DQTGlETAPMQ0wCwYDVQQDDAR1c2VyplwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAI7LgKEDN49fq08G3v8kXa8GmlqqLtAy4OKDkbfvtQG/rHvki19isRCat3GPNKhFp5hUrVApPOkC7pwKrtCh3u8CAwEAATAVMBMGCSsGAQUFBwUBAQwGZm9vMTIzoYHHoHOgE6QRMA8xDTALBgNVBAMMBHVzZXIwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAjsuAoQM3j1+rTwbe/yRdrwaaWqou0DLg4oORt++1Ab+se+SLX2KxEJq3cY80qEWnmFStUCk86QLunAqu0KHe7wIDAQABMA0GCSqGSIb3DQEBBQUAA0EAFqKulRt/zRzvd+HzPpYTBWd4g7tKaFAZEb+vHbt0hojMLq20kqIE1t2aYpezjGZdV4zyQJPUOi5VYfLesujvjqBDA0EAX8AwJDr+yzjxv3067lsiINO75x5GqqR644GogxEIH1cyKkRbhlixw8qLdfWt2VShw1TdliLRkuZA5tCOtWlhlw==").getBytes());

    /** CMP initial request message, created with BouncyCastle 1.47, with RAVerified POP and PBE protection */
    static byte[] bc147rapopir = Base64.decode(("MIIBcjCBowIBAqQRMA8xDTALBgNVBAMMBHVzZXKkFTATMREwDwYDVQQDDAhBZG1pbkNBMaARGA8yMDExMDYwNzA3MTkzMlqhQDA+BgkqhkiG9n0HQg0wMQQUuntpSbyZ6c92+PuwG/hPugOq/C4wBwYFKw4DAhoCAgPoMAwGCCsGAQUFCAECBQCiBwQFS2V5SWSkCgQIP80XoNAlmuylCgQIP80XoNAlmuyggbAwga0wgaowgaUCAXswgYijFTATMREwDwYDVQQDDAhBZG1pbkNBMaURMA8xDTALBgNVBAMMBHVzZXKmXDANBgkqhkiG9w0BAQEFAANLADBIAkEAmNU532N0oqncVerEF6QUugLlyC9RfFwO9yRgeLlejbV86j/0sqIs//Zc1Y0SHLqV0pIHTuf3pke0jPJYVHIN6wIDAQABMBUwEwYJKwYBBQUHBQEBDAZmb28xMjOAAKAXAxUAeZsIGZFSEUpsNBtfA17aHxwjs/Y=").getBytes());
    /** CMP initial request message, created with BouncyCastle 1.47, with POPOSigningKey POP and signature protection */
    static byte[] bc147sigpopir = Base64.decode(("MIIBvzByAgECpBEwDzENMAsGA1UEAwwEdXNlcqQVMBMxETAPBgNVBAMMCEFkbWluQ0ExoBEYDzIwMTEwNjA3MDcxOTMyWqEPMA0GCSqGSIb3DQEBBQUAogcEBUtleUlkpAoECD/NF6DQJZrspQoECD/NF6DQJZrsoIIBAjCB/zCB/DCBpQIBezCBiKMVMBMxETAPBgNVBAMMCEFkbWluQ0ExpREwDzENMAsGA1UEAwwEdXNlcqZcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCY1TnfY3SiqdxV6sQXpBS6AuXIL1F8XA73JGB4uV6NtXzqP/Syoiz/9lzVjRIcupXSkgdO5/emR7SM8lhUcg3rAgMBAAEwFTATBgkrBgEFBQcFAQEMBmZvbzEyM6FSMA0GCSqGSIb3DQEBBQUAA0EAGsbIFtJIwveAYvRzLtFwx9M2CFqr/tLbllNgogcljzhJ3bab4gsh25PZC2bvG7T3ieQXj8fR2KGp6xUQjl4Ii6BDA0EASsMjeH6FutbH9wIGr/5smC59E3+z+RjnhhFyUxgMMLV7wKZbKtoJUzKjjc2Hh7IzCjt6sBmcf0dBMpR1Qq8OWA==").getBytes());

    /** CMP initial request message, created with EJBCA 4.0.2 code, with RAVerified POP and PBE protection */
    static byte[] novosecrapopir = Base64.decode(("MIICwjCCAQ8CAQKkVzBVMSYwJAYDVQQDDB1hYmMxMjNycnktNDM3MTkzOTU0MzkxMzYzOTg4MTEeMBwGA1UECgwVUHJpbWVLZXkgU29sdXRpb25zIEFCMQswCQYDVQQGEwJTRaQ5MDcxETAPBgNVBAMMCEFkbWluQ0ExMRUwEwYDVQQKDAxFSkJDQSBTYW1wbGUxCzAJBgNVBAYTAlNFoBEYDzIwMTEwNTMwMDkwNTQyWqEwMC4GCSqGSIb2fQdCDTAhBAZmb28xMjMwBwYFKw4DAhoCAgI3MAoGCCqGSIb3DQIHogkEB215a2V5aWSkEgQQJV0C01odEXcv7BG4uW6bO6USBBD2+lerPhUqwF4Az6Vemh2yoIIBkjCCAY4wggGKMIIBawIBBDCCAWSjOTA3MREwDwYDVQQDDAhBZG1pbkNBMTEVMBMGA1UECgwMRUpCQ0EgU2FtcGxlMQswCQYDVQQGEwJTRaQkoBEYDzIwMDMwMjExMDAyMTIwWqEPFw0xMTA1MzAwOTA1NDJapVcwVTEmMCQGA1UEAwwdYWJjMTIzcnJ5LTQzNzE5Mzk1NDM5MTM2Mzk4ODExHjAcBgNVBAoMFVByaW1lS2V5IFNvbHV0aW9ucyBBQjELMAkGA1UEBhMCU0WmXDANBgkqhkiG9w0BAQEFAANLADBIAkEAkM6qeA9Vkaz+NHyejepEgBrwvbCKIta3CpG+mp+0zayL7NA90AknRsW7A3sX0i3IEDY3wvUhJ1+yc53M89OaKQIDAQABqUowOwYDVR0RBDQwMoEQZm9vZW1haWxAYmFyLmNvbaAeBgorBgEEAYI3FAIDoBAMDmZvb3VwbkBiYXIuY29tMAsGA1UdDwQEAwIF4KACBQAwFTATBgkrBgEFBQcFAQEMBmZvbzEyM6AXAxUAnJ0lrTWxB+sKIdj1oCSYfJ1/Fpk=").getBytes());
    
    /** CMP initial request message, created with EJBCA 4.0.2 code, with signature POP (no POPOSigningKey) and signature protection */
    static byte[] novosecsigpopir = Base64.decode(("MIIEUDCB4AIBAqRWMFQxJTAjBgNVBAMMHGFiYzEyM3JyeTI5NDI4MTI4MDE5ODA2Njg4NTMxHjAcBgNVBAoMFVByaW1lS2V5IFNvbHV0aW9ucyBBQjELMAkGA1UEBhMCU0WkOTA3MREwDwYDVQQDDAhBZG1pbkNBMTEVMBMGA1UECgwMRUpCQ0EgU2FtcGxlMQswCQYDVQQGEwJTRaARGA8yMDExMDUzMDEyNTQyMVqhDTALBgkqhkiG9w0BAQWkEgQQFoG/DzbmQiksb5Yrrih6xqUSBBCcgBl5fXla0Ilj/Qib+iVPoIIB4TCCAd0wggHZMIIBagIBBDCCAWOjOTA3MREwDwYDVQQDDAhBZG1pbkNBMTEVMBMGA1UECgwMRUpCQ0EgU2FtcGxlMQswCQYDVQQGEwJTRaQkoBEYDzIwMDMwMjExMDAyMTIwWqEPFw0xMTA1MzAxMjU0MjFapVYwVDElMCMGA1UEAwwcYWJjMTIzcnJ5Mjk0MjgxMjgwMTk4MDY2ODg1MzEeMBwGA1UECgwVUHJpbWVLZXkgU29sdXRpb25zIEFCMQswCQYDVQQGEwJTRaZcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDFiXtcgIBhL9FFnNASa0ezOX513vxlkWLTgkVqS0TEv/wmTxNZ4wgTM9zRYGDK/MVKiOzPREoHPwib0F8X4OwdAgMBAAGpSjA7BgNVHREENDAygRBmb29lbWFpbEBiYXIuY29toB4GCisGAQQBgjcUAgOgEAwOZm9vdXBuQGJhci5jb20wCwYDVR0PBAQDAgXgoVIwUDALBgkqhkiG9w0BAQUDQQANpvmT5H0S9nh7O2WD5+MgHvu0FT7umak741nuPo3fAgKJJbzMF6rG5/lwE7tNAnAZKVzuhAF9pSk5KjxDIl0UMBUwEwYJKwYBBQUHBQEBDAZmb28xMjOgQwNBAA+6Is7z6dNIMMQjEpwk2CEx44rE1KhehrrSS4wqPgkcE6MUt7+IBq/zOD3IE4DT/YoyDIx9bIugIJj8pJiJAbahggE/MIIBOzCCATcwgeKgAwIBAgIIN5Wx1B7SXAEwDQYJKoZIhvcNAQEFBQAwGDEWMBQGA1UEAwwNQ01QIFNpZ24gVGVzdDAeFw0xMTA1MzAxMjQ0MjFaFw0yMTA1MjcxMjU0MjFaMBgxFjAUBgNVBAMMDUNNUCBTaWduIFRlc3QwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAxYl7XICAYS/RRZzQEmtHszl+dd78ZZFi04JFaktExL/8Jk8TWeMIEzPc0WBgyvzFSojsz0RKBz8Im9BfF+DsHQIDAQABoxAwDjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBBQUAA0EAvdqiow8CoVzeupH6AtR6IbfM87KPV8TyxiPk5Qt3Mwst8g2nLP7CqMYjlufPFH+FvGoZN00zEJZcfeqwhtClCQ==").getBytes());

}
