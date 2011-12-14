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
package org.ejbca.core.protocol.ocsp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Hashtable;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.RespID;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.protocol.ocsp.OcspUtilMockups.MockDSAPublicKey;
import org.ejbca.core.protocol.ocsp.OcspUtilMockups.MockECDSAPublicKey;
import org.ejbca.core.protocol.ocsp.OcspUtilMockups.MockRSAPublicKey;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author tomas
 * @version $Id$
 *
 */
public class OcspUtilTest {
	
	@Before
	public void setUp() throws Exception {
		CryptoProviderTools.installBCProviderIfNotAvailable();
	}

	@Test
	public void test01CreateOCSPCAServiceResponse() throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
		ks.load(new ByteArrayInputStream(sceprap12), "foo123".toCharArray());
		String providerName = "BC";
		X509Certificate racert = (X509Certificate)ks.getCertificate("Scep RA");
		Certificate[] chain = ks.getCertificateChain("Scep RA");
		assertEquals(3, chain.length);
		X509Certificate cacert = (X509Certificate)chain[1];
		String signer = CertTools.getSubjectDN(chain[0]);
		assertEquals("CN=Scep RA,O=PrimeKey,C=SE", signer);
		PrivateKey privKey = (PrivateKey)ks.getKey("Scep RA", "foo123".toCharArray());
		X509Certificate[] certChain = new X509Certificate[chain.length];
		for (int i=0;i<chain.length;i++) {
			certChain[i] = (X509Certificate)chain[i];
		}
		// Everything looks OK, lets get started with the real tests.
		
		// An OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, racert.getSerialNumber()));
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();

        // A response to create
		ArrayList<OCSPResponseItem> responseList = new ArrayList<OCSPResponseItem>();
		CertificateID certId = req.getRequestList()[0].getCertID();
		responseList.add(new OCSPResponseItem(certId, new UnknownStatus(), 0));

		// First check that the whole chain is included and the responderId is keyHash
		OCSPCAServiceRequest ocspServiceReq = new OCSPCAServiceRequest(req, responseList, null, "SHA1WithRSA;SHA1WithDSA;SHA1WithECDSA", true);
		ocspServiceReq.setRespIdType(OcspConfiguration.RESPONDERIDTYPE_KEYHASH);

		OCSPCAServiceResponse response = OCSPUtil.createOCSPCAServiceResponse(ocspServiceReq, privKey, providerName, certChain);
		BasicOCSPResp basicResp = response.getBasicOCSPResp();
		X509Certificate[] respCerts = basicResp.getCerts("BC");
		assertEquals(3, respCerts.length); // Certificate chain included
		RespID respId = basicResp.getResponderId();
		RespID testKeyHash = new RespID(racert.getPublicKey());
		RespID testName = new RespID(racert.getSubjectX500Principal());
		assertEquals(respId, testKeyHash);
		assertFalse(respId.equals(testName));

		// Second check that the whole chain is NOT included and the responderId is Name
		ocspServiceReq = new OCSPCAServiceRequest(req, responseList, null, "SHA1WithRSA;SHA1WithDSA;SHA1WithECDSA", false);
		ocspServiceReq.setRespIdType(OcspConfiguration.RESPONDERIDTYPE_NAME);
		response = OCSPUtil.createOCSPCAServiceResponse(ocspServiceReq, privKey, providerName, certChain);
		basicResp = response.getBasicOCSPResp();
		respCerts = basicResp.getCerts("BC");
		assertEquals(1, respCerts.length); // Certificate chain included
		respId = basicResp.getResponderId();
		assertFalse(respId.equals(testKeyHash));
		assertEquals(respId, testName);

		// Third do some verification
		basicResp.verify(racert.getPublicKey(), "BC");
		SingleResp[] responses = basicResp.getResponses();
		assertEquals(1, responses.length);
		SingleResp resp = responses[0];
		CertificateID myid = resp.getCertID();
		assertEquals(certId, myid);
	}

	@Test
	public void test02getSigningAlgFromAlgSelection() throws Exception {
		
		RSAPublicKey rsa = new MockRSAPublicKey();
		assertEquals("SHA1WithRSA", OCSPUtil.getSigningAlgFromAlgSelection("SHA1WithRSA;SHA1WithECDSA", rsa));
		assertEquals("SHA1WithRSA", OCSPUtil.getSigningAlgFromAlgSelection("SHA256WithECDSA;SHA1WithECDSA;SHA1WithRSA", rsa));
		assertEquals("SHA1WithRSA", OCSPUtil.getSigningAlgFromAlgSelection("SHA1WithRSA", rsa));
		assertEquals("SHA1WithRSA", OCSPUtil.getSigningAlgFromAlgSelection("SHA1WithECDSA;SHA1WithRSA", rsa));

		ECPublicKey ecdsa = new MockECDSAPublicKey();
		assertEquals("SHA1WithECDSA", OCSPUtil.getSigningAlgFromAlgSelection("SHA1WithECDSA;SHA1WithDSA", ecdsa));
		assertEquals("SHA1WithECDSA", OCSPUtil.getSigningAlgFromAlgSelection("SHA1WithDSA;SHA1WithRSA;SHA1WithECDSA", ecdsa));
		assertEquals("SHA1WithECDSA", OCSPUtil.getSigningAlgFromAlgSelection("SHA1WithECDSA", ecdsa));
		assertEquals("SHA1WithECDSA", OCSPUtil.getSigningAlgFromAlgSelection("SHA1WithDSA;SHA1WithECDSA", ecdsa));
		
		DSAPublicKey dsa = new MockDSAPublicKey();
		assertEquals("SHA1WithDSA", OCSPUtil.getSigningAlgFromAlgSelection("SHA1WithECDSA;SHA1WithDSA", dsa));
		assertEquals("SHA1WithDSA", OCSPUtil.getSigningAlgFromAlgSelection("SHA256WithECDSA;SHA1WithECDSA;SHA1WithDSA", dsa));
		assertEquals("SHA1WithDSA", OCSPUtil.getSigningAlgFromAlgSelection("SHA1WithDSA", dsa));
		assertEquals("SHA1WithDSA", OCSPUtil.getSigningAlgFromAlgSelection("SHA1WithECDSA;SHA1WithDSA", dsa));
		
		assertNull(OCSPUtil.getSigningAlgFromAlgSelection("", dsa));
	}
	
	
	
	
	
	private static byte[] sceprap12 = Base64
	.decode(("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")
			.getBytes());
}
