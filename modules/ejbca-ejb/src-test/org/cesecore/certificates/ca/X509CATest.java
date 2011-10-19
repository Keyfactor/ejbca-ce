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
package org.cesecore.certificates.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.NullCryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;
import org.junit.Test;

/** JUnit test for X.509 CA
 * 
 * @version $Id$
 */
public class X509CATest {

	public static final String CADN = "CN=TEST";
	
	public X509CATest() {
		CryptoProviderTools.installBCProvider();
	}
	@Test
	public void testX509CABasicOperations() throws Exception {
		
        X509CA x509ca = createTestCA(CADN);
        Certificate cacert = x509ca.getCACertificate();
        
        // Start by creating a PKCS7
        byte[] p7 = x509ca.createPKCS7(cacert, true);
        assertNotNull(p7);
        CMSSignedData s = new CMSSignedData(p7);
        CertStore certstore = s.getCertificatesAndCRLs("Collection","BC");
        Collection<?> certs = certstore.getCertificates(null);
        assertEquals(2, certs.size());
        p7 = x509ca.createPKCS7(cacert, false);
        assertNotNull(p7);
        s = new CMSSignedData(p7);
        certstore = s.getCertificatesAndCRLs("Collection","BC");
        certs = certstore.getCertificates(null);
        assertEquals(1, certs.size());
        
		// Create a certificate request (will be pkcs10)
        byte[] req = x509ca.createRequest(null, "SHA1WithRSA", cacert, CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        PKCS10CertificationRequest p10 = new PKCS10CertificationRequest(req);
        assertNotNull(p10);
        String dn = p10.getCertificationRequestInfo().getSubject().toString();
        assertEquals(CADN, dn);
        
        // Make a request with some pkcs11 attributes as well
		Collection<DEREncodable> attributes = new ArrayList<DEREncodable>();
		// Add a subject alternative name
		ASN1EncodableVector altnameattr = new ASN1EncodableVector();
		altnameattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
		GeneralNames san = CertTools.getGeneralNamesFromAltName("dNSName=foobar.bar.com");
		ByteArrayOutputStream extOut = new ByteArrayOutputStream();
		DEROutputStream derOut = new DEROutputStream(extOut);
		try {
			derOut.writeObject(san);
		} catch (IOException e) {
			throw new IllegalArgumentException("error encoding value: " + e);
		}
		Vector<DERObjectIdentifier> oidvec = new Vector<DERObjectIdentifier>();
		oidvec.add(X509Extensions.SubjectAlternativeName);
		Vector<X509Extension> valuevec = new Vector<X509Extension>();
		valuevec.add(new X509Extension(false, new DEROctetString(extOut.toByteArray())));
		X509Extensions exts = new X509Extensions(oidvec, valuevec);
		altnameattr.add(new DERSet(exts));
        // Add a challenge password as well
        ASN1EncodableVector pwdattr = new ASN1EncodableVector();
        pwdattr.add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword); 
        ASN1EncodableVector pwdvalues = new ASN1EncodableVector();
        pwdvalues.add(new DERUTF8String("foobar123"));
        pwdattr.add(new DERSet(pwdvalues));
        attributes.add(new DERSequence(altnameattr));
        attributes.add(new DERSequence(pwdattr));
        // create the p10
        req = x509ca.createRequest(attributes, "SHA1WithRSA", cacert, CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        p10 = new PKCS10CertificationRequest(req);
        assertNotNull(p10);
        dn = p10.getCertificationRequestInfo().getSubject().toString();
        assertEquals(CADN, dn);
        ASN1Set attrs = p10.getCertificationRequestInfo().getAttributes();
        assertEquals(2, attrs.size());
        PKCS10RequestMessage p10msg = new PKCS10RequestMessage(p10);
        assertEquals("foobar123", p10msg.getPassword());
        assertEquals("dNSName=foobar.bar.com", p10msg.getRequestAltNames());

        // Try to sign the request, will return null
        byte[] signedReq = x509ca.signRequest(p10.getDEREncoded(), false, false);
        assertNull(signedReq);
        
        // Generate a client certificate and check that it was generated correctly
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", EndEntityConstants.USER_ENDUSER, 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        KeyPair keypair = KeyTools.genKeys("512", "RSA");
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = x509ca.generateCertificate(user, keypair.getPublic(), 0, null, 10L, cp, "00000");
        assertNotNull(usercert);
        assertEquals("CN=User", CertTools.getSubjectDN(usercert));
        assertEquals(CADN, CertTools.getIssuerDN(usercert));
        assertEquals("SHA256WithRSAEncryption", AlgorithmTools.getCertSignatureAlgorithmNameAsString(usercert));
        assertEquals(new String(CertTools.getSubjectKeyId(cacert)), new String(CertTools.getAuthorityKeyId(usercert)));
        assertEquals("user@user.com", CertTools.getEMailAddress(usercert));
        assertEquals("rfc822name=user@user.com", CertTools.getSubjectAlternativeName(usercert));
        assertNull(CertTools.getUPNAltName(usercert));
        assertFalse(CertTools.isSelfSigned(usercert));
        usercert.verify(x509ca.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        usercert.verify(x509ca.getCACertificate().getPublicKey());
        assertTrue(CertTools.isCA(x509ca.getCACertificate()));
        assertFalse(CertTools.isCA(usercert));
        assertEquals("1.1.1.2", CertTools.getCertificatePolicyId(usercert, 0));
        X509Certificate cert = (X509Certificate)usercert;
        boolean[] ku = cert.getKeyUsage();
        assertTrue(ku[0]);
        assertTrue(ku[1]);
        assertTrue(ku[2]);
        assertFalse(ku[3]);
        assertFalse(ku[4]);
        assertFalse(ku[5]);
        assertFalse(ku[6]);
        assertFalse(ku[7]);
        int bcku = CertTools.sunKeyUsageToBC(ku);
        assertEquals(X509KeyUsage.digitalSignature|X509KeyUsage.nonRepudiation|X509KeyUsage.keyEncipherment, bcku);
        
        // Create a CRL
        Collection<RevokedCertInfo> revcerts = new ArrayList<RevokedCertInfo>();
        CRL crl = x509ca.generateCRL(revcerts, 1);
        assertNotNull(crl);
        X509CRL xcrl = (X509CRL)crl;
        assertEquals(CADN, CertTools.getIssuerDN(xcrl));
        Set<?> set = xcrl.getRevokedCertificates();
        assertNull(set);
        BigInteger num = CrlExtensions.getCrlNumber(xcrl);
        assertEquals(1, num.intValue());
        BigInteger deltanum = CrlExtensions.getDeltaCRLIndicator(xcrl);
        assertEquals(-1, deltanum.intValue());
        // Revoke some cert
        Date revDate = new Date();
        revcerts.add(new RevokedCertInfo(CertTools.getFingerprintAsString(usercert), CertTools.getSerialNumber(usercert), revDate, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, CertTools.getNotAfter(usercert)));
        xcrl = (X509CRL)x509ca.generateCRL(revcerts, 2);
        set = xcrl.getRevokedCertificates();
        assertEquals(1, set.size());
        num = CrlExtensions.getCrlNumber(xcrl);
        assertEquals(2, num.intValue());
        X509CRLEntry entry = (X509CRLEntry)set.iterator().next();
        assertEquals(CertTools.getSerialNumber(usercert).toString(), entry.getSerialNumber().toString());
        assertEquals(revDate.toString(), entry.getRevocationDate().toString());
        // Getting the revocation reason is a pita...
        byte[] extval = entry.getExtensionValue(X509Extensions.ReasonCode.getId());
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(extval));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        DERObject obj = aIn.readObject();
        CRLReason reason = new CRLReason((DEREnumerated)obj);
        assertEquals("CRLReason: certificateHold", reason.toString());
        //DEROctetString ostr = (DEROctetString)obj;
        
        // Create a delta CRL
        revcerts = new ArrayList<RevokedCertInfo>();
        crl = x509ca.generateDeltaCRL(revcerts, 3, 2);
        assertNotNull(crl);
        xcrl = (X509CRL)crl;
        assertEquals(CADN, CertTools.getIssuerDN(xcrl));
        set = xcrl.getRevokedCertificates();
        assertNull(set);
        num = CrlExtensions.getCrlNumber(xcrl);
        assertEquals(3, num.intValue());
        deltanum = CrlExtensions.getDeltaCRLIndicator(xcrl);
        assertEquals(2, deltanum.intValue());
        revcerts.add(new RevokedCertInfo(CertTools.getFingerprintAsString(usercert), CertTools.getSerialNumber(usercert), revDate, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, CertTools.getNotAfter(usercert)));
        xcrl = (X509CRL)x509ca.generateDeltaCRL(revcerts, 4, 3);
        deltanum = CrlExtensions.getDeltaCRLIndicator(xcrl);
        assertEquals(3, deltanum.intValue());
        set = xcrl.getRevokedCertificates();
        assertEquals(1, set.size());
        entry = (X509CRLEntry)set.iterator().next();
        assertEquals(CertTools.getSerialNumber(usercert).toString(), entry.getSerialNumber().toString());
        assertEquals(revDate.toString(), entry.getRevocationDate().toString());
        // Getting the revocation reason is a pita...
        extval = entry.getExtensionValue(X509Extensions.ReasonCode.getId());
        aIn = new ASN1InputStream(new ByteArrayInputStream(extval));
        octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        obj = aIn.readObject();
        reason = new CRLReason((DEREnumerated)obj);
        assertEquals("CRLReason: certificateHold", reason.toString());
	}
	
    /**
     * Tests the extension CRL Distribution Point on CRLs
     * 
     */
	@Test
    public void testCRLDistPointOnCRL() throws Exception {

        X509CA ca = createTestCA(CADN);

        final String cdpURL = "http://www.ejbca.org/foo/bar.crl";
        X509CAInfo cainfo = (X509CAInfo) ca.getCAInfo();

        cainfo.setUseCrlDistributionPointOnCrl(true);
        cainfo.setDefaultCRLDistPoint(cdpURL);
        ca.updateCA(cainfo);
        
        Collection<RevokedCertInfo> revcerts = new ArrayList<RevokedCertInfo>();
        CRL crl = ca.generateCRL(revcerts, 1);
        assertNotNull(crl);
        X509CRL xcrl = (X509CRL)crl;

        byte[] cdpDER = xcrl.getExtensionValue(X509Extensions.IssuingDistributionPoint.getId());
        assertNotNull("CRL has no distribution points", cdpDER);

        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(cdpDER));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        IssuingDistributionPoint cdp = new IssuingDistributionPoint((ASN1Sequence) aIn.readObject());
        DistributionPointName distpoint = cdp.getDistributionPoint();

        assertEquals("CRL distribution point is different", cdpURL, ((DERIA5String) ((GeneralNames) distpoint.getName()).getNames()[0].getName()).getString());

        cainfo.setUseCrlDistributionPointOnCrl(false);
        cainfo.setDefaultCRLDistPoint(null);
        ca.updateCA(cainfo);
        crl = ca.generateCRL(revcerts, 1);
        xcrl = (X509CRL)crl;
        assertNull("CRL has distribution points", xcrl.getExtensionValue(X509Extensions.CRLDistributionPoints.getId()));
    }

    /**
     * Tests the extension Freshest CRL DP.
     * 
     * @throws Exception
     *             in case of error.
     */
	@Test
    public void testCRLFreshestCRL() throws Exception {
        X509CA ca = createTestCA(CADN);
        final String cdpURL = "http://www.ejbca.org/foo/bar.crl";
        final String freshestCdpURL = "http://www.ejbca.org/foo/delta.crl";
        X509CAInfo cainfo = (X509CAInfo) ca.getCAInfo();

        cainfo.setUseCrlDistributionPointOnCrl(true);
        cainfo.setDefaultCRLDistPoint(cdpURL);
        cainfo.setCADefinedFreshestCRL(freshestCdpURL);
        ca.updateCA(cainfo);

        Collection<RevokedCertInfo> revcerts = new ArrayList<RevokedCertInfo>();
        CRL crl = ca.generateCRL(revcerts, 1);
        assertNotNull(crl);
        X509CRL xcrl = (X509CRL)crl;

        byte[] cFreshestDpDER = xcrl.getExtensionValue(X509Extensions.FreshestCRL.getId());
        assertNotNull("CRL has no Freshest Distribution Point", cFreshestDpDER);

        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(cFreshestDpDER));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        CRLDistPoint cdp = new CRLDistPoint((ASN1Sequence) aIn.readObject());
        DistributionPoint[] distpoints = cdp.getDistributionPoints();

        assertEquals("More CRL Freshest distributions points than expected", 1, distpoints.length);
        assertEquals("Freshest CRL distribution point is different", freshestCdpURL, ((DERIA5String) ((GeneralNames) distpoints[0].getDistributionPoint()
                .getName()).getNames()[0].getName()).getString());

        cainfo.setUseCrlDistributionPointOnCrl(false);
        cainfo.setDefaultCRLDistPoint(null);
        cainfo.setCADefinedFreshestCRL(null);
        ca.updateCA(cainfo);

        crl = ca.generateCRL(revcerts, 1);
        assertNotNull(crl);
        xcrl = (X509CRL)crl;
        assertNull("CRL has freshest crl extension", xcrl.getExtensionValue(X509Extensions.FreshestCRL.getId()));
    }

	@Test
	public void testStoreAndLoad() throws Exception {
		X509CA ca = createTestCA(CADN);
		
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", EndEntityConstants.USER_ENDUSER, 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        KeyPair keypair = KeyTools.genKeys("512", "RSA");
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = ca.generateCertificate(user, keypair.getPublic(), 0, null, 10L, cp, "00000");
        String authKeyId = new String(Hex.encode(CertTools.getAuthorityKeyId(usercert)));
        String keyhash = CertTools.getFingerprintAsString(ca.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN).getEncoded());

        // Save CA data
		Object o = ca.saveData();
		
		// Restore CA from data (and other things)
		X509CA ca1 = new X509CA((HashMap)o, 777, CADN, "test", CAConstants.CA_ACTIVE, new Date(), new Date());

		Certificate usercert1 = ca.generateCertificate(user, keypair.getPublic(), 0, null, 10L, cp, "00000");

        String authKeyId1 = new String(Hex.encode(CertTools.getAuthorityKeyId(usercert1)));
        String keyhash1 = CertTools.getFingerprintAsString(ca1.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN).getEncoded());
        assertEquals(authKeyId, authKeyId1);
        assertEquals(keyhash, keyhash1);
        
        CAInfo cainfo = ca.getCAInfo();
        CAData cadata = new CAData(cainfo.getSubjectDN(), cainfo.getName(), cainfo.getStatus(), ca);

        CA ca2 = cadata.getCA();
		Certificate usercert2 = ca.generateCertificate(user, keypair.getPublic(), 0, null, 10L, cp, "00000");
        String authKeyId2 = new String(Hex.encode(CertTools.getAuthorityKeyId(usercert2)));
        String keyhash2 = CertTools.getFingerprintAsString(ca2.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN).getEncoded());
        assertEquals(authKeyId, authKeyId2);
        assertEquals(keyhash, keyhash2);
        
        // Check CAinfo and CAtokeninfo
        cainfo = ca.getCAInfo();
        CATokenInfo catokeninfo = cainfo.getCATokenInfo();
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, catokeninfo.getSignatureAlgorithm());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, catokeninfo.getEncryptionAlgorithm());
        assertEquals(SoftCryptoToken.class.getName(), catokeninfo.getClassPath());
        assertEquals(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, catokeninfo.getKeySequenceFormat());
        
        cainfo = ca2.getCAInfo();
        catokeninfo = cainfo.getCATokenInfo();
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, catokeninfo.getSignatureAlgorithm());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, catokeninfo.getEncryptionAlgorithm());
        assertEquals(SoftCryptoToken.class.getName(), catokeninfo.getClassPath());
        assertEquals(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, catokeninfo.getKeySequenceFormat());

	}
	
	

	@Test
	public void testExtendedCAServices() throws Exception {
		X509CA ca = createTestCA(CADN);
		assertEquals(ca.getExternalCAServiceTypes().size(), 0);
		assertNull(ca.getExtendedCAServiceInfo(1));
		
		CAInfo info = ca.getCAInfo();
		Collection<ExtendedCAServiceInfo> infos = new ArrayList<ExtendedCAServiceInfo>();
		infos.add(new MyExtendedCAServiceInfo(0));
		info.setExtendedCAServiceInfos(infos);
		ca.updateCA(info);
		
		assertEquals(ca.getExternalCAServiceTypes().size(), 1);
		assertNotNull(ca.getExtendedCAServiceInfo(4711));
		assertNull(ca.getExtendedCAServiceInfo(1));
		assertNotNull("org.cesecore.certificates.ca.MyExtendedCAServiceInfo", ca.getExtendedCAServiceInfo(4711).getClass().getName());
		
		// Try to run it
		assertEquals(0, MyExtendedCAService.didrun);
		ca.extendedService(new MyExtendedCAServiceRequest());
		assertEquals(1, MyExtendedCAService.didrun);
		ca.extendedService(new MyExtendedCAServiceRequest());
		assertEquals(2, MyExtendedCAService.didrun);
		
		// Does is store and load ok?
		Object o = ca.saveData();		
		// Restore CA from data (and other things)
		X509CA ca1 = new X509CA((HashMap)o, 777, CADN, "test", CAConstants.CA_ACTIVE, new Date(), new Date());
		ca1.extendedService(new MyExtendedCAServiceRequest());
		assertEquals(3, MyExtendedCAService.didrun);
	}

	@Test
	public void testCAInfo() throws Exception {
		X509CA ca = createTestCA(CADN);
		assertEquals(CAConstants.CA_ACTIVE, ca.getStatus());
		assertEquals(CAConstants.CA_ACTIVE, ca.getCAInfo().getStatus());
		ca.setStatus(CAConstants.CA_OFFLINE);
		assertEquals(CAConstants.CA_OFFLINE, ca.getStatus());
		assertEquals(CAConstants.CA_OFFLINE, ca.getCAInfo().getStatus());
	}
	
	@Test
	public void testInvalidSignatureAlg() throws Exception {
		try {
			createTestCA(CADN, "MD5WithRSA");
			fail("This should throw because md5withRSA is not an allowed signature algorithm. It is vulnerable.");
		} catch (InvalidAlgorithmException e) {
			// NOPMD: this is what we want
		}
		X509CA ca = createTestCA(CADN, "SHA1WithRSA");
		assertNotNull("should work to create a CA", ca);
		CAToken token = new CAToken(new NullCryptoToken());
		ca.setCAToken(token);
	}
	
	private static X509CA createTestCA(final String cadn) throws Exception {
		return createTestCA(cadn, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
	}
	private static X509CA createTestCA(final String cadn, final String sigAlg) throws Exception {
		// Create catoken
		Properties prop = new Properties();
    	prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
    	prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS); 
    	prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        // Set key generation property, since we have no old keys to generate the same sort
        prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, "512");
        CryptoToken cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), prop, null, 666);
        cryptoToken.generateKeyPair("512", CAToken.SOFTPRIVATESIGNKEYALIAS);
        cryptoToken.generateKeyPair("512", CAToken.SOFTPRIVATEDECKEYALIAS);
        
		CAToken catoken = new CAToken(cryptoToken);
		// Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
		catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
		catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
		catoken.setSignatureAlgorithm(sigAlg);
		catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);

		CATokenInfo catokeninfo = catoken.getTokenInfo();
        // No extended services
        ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();

        X509CAInfo cainfo = new X509CAInfo(cadn, "TEST", CAConstants.CA_ACTIVE, new Date(), "", CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 3650, null, // Expiretime
                CAInfo.CATYPE_X509, CAInfo.SELFSIGNED, (Collection<Certificate>) null, catokeninfo, "JUnit RSA CA", -1, null, null, // PolicyId
                24, // CRLPeriod
                0, // CRLIssueInterval
                10, // CRLOverlapTime
                10, // Delta CRL period
                new ArrayList<Integer>(), true, // Authority Key Identifier
                false, // Authority Key Identifier Critical
                true, // CRL Number
                false, // CRL Number Critical
                null, // defaultcrldistpoint
                null, // defaultcrlissuer
                null, // defaultocsplocator
                null, // defaultfreshestcrl
                true, // Finish User
                extendedcaservices, false, // use default utf8 settings
                new ArrayList<Integer>(), // Approvals Settings
                1, // Number of Req approvals
                false, // Use UTF8 subject DN by default
                true, // Use LDAP DN order by default
                false, // Use CRL Distribution Point on CRL
                false, // CRL Distribution Point on CRL critical
                true, true, // isDoEnforceUniquePublicKeys
                true, // isDoEnforceUniqueDistinguishedName
                false, // isDoEnforceUniqueSubjectDNSerialnumber
                true, // useCertReqHistory
                true, // useUserStorage
                true, // useCertificateStorage
                null //cmpRaAuthSecret
        );
        
        X509CA x509ca = new X509CA(cainfo);
        x509ca.setCAToken(catoken);
        // A CA certificate
		X509Certificate cacert = CertTools.genSelfCert(cadn, 10L, "1.1.1.1", catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), "SHA256WithRSA", true);
		assertNotNull(cacert);
        Collection<Certificate> cachain = new ArrayList<Certificate>();
        cachain.add(cacert);
        x509ca.setCertificateChain(cachain);
        // Now our CA should be operational
        return x509ca;
	}


}
