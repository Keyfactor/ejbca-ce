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
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CeSecoreNameStyle;
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

	// This will be an empty list of custom certificate extensions
	private final AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();

	public X509CATest() {
		CryptoProviderTools.installBCProvider();
	}

	@Test
	public void testX509CABasicOperationsRSA() throws Exception {
	    doTestX509CABasicOperations(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1);
        // AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1 uses small w in With. Test with capital as well
        // because this was used previously so need to be supported for upgraded systems.
        doTestX509CABasicOperations("SHA256WithRSAandMGF1");
	}

	@Test
    public void testX509CABasicOperationsGOST() throws Exception {
	    assumeTrue(AlgorithmTools.isGost3410Enabled());
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410);
    }

    @Test
    public void testX509CABasicOperationsDSTU() throws Exception {
        assumeTrue(AlgorithmTools.isDstu4145Enabled());
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145);
    }

    @Test
    public void testX509CABasicOperationsBrainpoolECC() throws Exception {
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA);
    }

    private void doTestX509CABasicOperations(String algName) throws Exception {
	    final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA x509ca = createTestCA(cryptoToken, CADN, algName, null, null);
        X509Certificate cacert = (X509Certificate) x509ca.getCACertificate();
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

        // Start by creating a PKCS7
        byte[] p7 = x509ca.createPKCS7(cryptoToken, cacert, true);
        assertNotNull(p7);
        CMSSignedData s = new CMSSignedData(p7);
        Store<X509CertificateHolder> certstore = s.getCertificates();
        Collection<X509CertificateHolder> certs = certstore.getMatches(null);
        assertEquals(2, certs.size());
        p7 = x509ca.createPKCS7(cryptoToken, cacert, false);
        assertNotNull(p7);
        s = new CMSSignedData(p7);
        certstore = s.getCertificates();
        certs = certstore.getMatches(null);
        assertEquals(1, certs.size());

		// Create a certificate request (will be pkcs10)
        byte[] req = x509ca.createRequest(cryptoToken, null, algName, cacert, CATokenConstants.CAKEYPURPOSE_CERTSIGN, cp, cceConfig);
        PKCS10CertificationRequest p10 = new PKCS10CertificationRequest(req);
        assertNotNull(p10);
        String dn = p10.getSubject().toString();
        assertEquals(CADN, dn);

        // Make a request with some pkcs10 attributes as well
		Collection<ASN1Encodable> attributes = new ArrayList<>();
		// Add a subject alternative name
		ASN1EncodableVector altnameattr = new ASN1EncodableVector();
		altnameattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
		GeneralNames san = CertTools.getGeneralNamesFromAltName("dNSName=foobar.bar.com");
		ExtensionsGenerator extgen = new ExtensionsGenerator();
		extgen.addExtension(Extension.subjectAlternativeName, false, san);
		Extensions exts = extgen.generate();
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
        req = x509ca.createRequest(cryptoToken, attributes, algName, cacert, CATokenConstants.CAKEYPURPOSE_CERTSIGN, cp, cceConfig);
        p10 = new PKCS10CertificationRequest(req);
        assertNotNull(p10);
        dn = p10.getSubject().toString();
        assertEquals(CADN, dn);
        Attribute[] attrs = p10.getAttributes();
        assertEquals(2, attrs.length);
        PKCS10RequestMessage p10msg = new PKCS10RequestMessage(new JcaPKCS10CertificationRequest(p10));
        assertEquals("foobar123", p10msg.getPassword());
        assertEquals("dNSName=foobar.bar.com", p10msg.getRequestAltNames());

        try {
            x509ca.createAuthCertSignRequest(cryptoToken, p10.getEncoded());
        } catch (UnsupportedOperationException e) {
            // Expected for a X509 CA
        }

        // Generate a client certificate and check that it was generated correctly
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com,dnsName=foo.bar.com,directoryName=CN=Tomas\\,O=PrimeKey\\,C=SE", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        KeyPair keypair = genTestKeyPair(algName);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = x509ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
        assertNotNull(usercert);
        assertEquals("CN=User", CertTools.getSubjectDN(usercert));
        assertEquals(CADN, CertTools.getIssuerDN(usercert));
        assertEquals(getTestKeyPairAlgName(algName).toUpperCase(), AlgorithmTools.getCertSignatureAlgorithmNameAsString(usercert).toUpperCase());
        assertEquals(new String(CertTools.getSubjectKeyId(cacert)), new String(CertTools.getAuthorityKeyId(usercert)));
        assertEquals("user@user.com", CertTools.getEMailAddress(usercert));
        // directoryName is turned around, but it's just for string reasons in cert objects because it is gotten (internally in BC) getRFC2253Name().
        assertEquals("rfc822name=user@user.com, dNSName=foo.bar.com, directoryName=c=SE\\,o=PrimeKey\\,cn=Tomas", CertTools.getSubjectAlternativeName(usercert));
        assertNull(CertTools.getUPNAltName(usercert));
        assertFalse(CertTools.isSelfSigned(usercert));
        usercert.verify(cryptoToken.getPublicKey(x509ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)));
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
        X509CRLHolder crl = x509ca.generateCRL(cryptoToken, revcerts, 1);
        assertNotNull(crl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());
        assertEquals(CADN, CertTools.getIssuerDN(xcrl));
        Set<?> set = xcrl.getRevokedCertificates();
        assertNull(set);
        BigInteger num = CrlExtensions.getCrlNumber(xcrl);
        assertEquals(1, num.intValue());
        BigInteger deltanum = CrlExtensions.getDeltaCRLIndicator(xcrl);
        assertEquals(-1, deltanum.intValue());
        // Revoke some cert
        Date revDate = new Date();
        revcerts.add(new RevokedCertInfo(CertTools.getFingerprintAsString(usercert).getBytes(), CertTools.getSerialNumber(usercert).toByteArray(), revDate.getTime(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, CertTools.getNotAfter(usercert).getTime()));
        crl = x509ca.generateCRL(cryptoToken, revcerts, 2);
        assertNotNull(crl);
        xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());
        set = xcrl.getRevokedCertificates();
        assertEquals(1, set.size());
        num = CrlExtensions.getCrlNumber(xcrl);
        assertEquals(2, num.intValue());
        X509CRLEntry entry = (X509CRLEntry)set.iterator().next();
        assertEquals(CertTools.getSerialNumber(usercert).toString(), entry.getSerialNumber().toString());
        assertEquals(revDate.toString(), entry.getRevocationDate().toString());
        // Getting the revocation reason is a pita...
        byte[] extval = entry.getExtensionValue(Extension.reasonCode.getId());
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(extval));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        ASN1Primitive obj = aIn.readObject();
        CRLReason reason = CRLReason.getInstance(obj);
        assertEquals("CRLReason: certificateHold", reason.toString());
        //DEROctetString ostr = (DEROctetString)obj;

        // Create a delta CRL
        revcerts = new ArrayList<RevokedCertInfo>();
        crl = x509ca.generateDeltaCRL(cryptoToken, revcerts, 3, 2);
        assertNotNull(crl);
        xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());
        assertEquals(CADN, CertTools.getIssuerDN(xcrl));
        set = xcrl.getRevokedCertificates();
        assertNull(set);
        num = CrlExtensions.getCrlNumber(xcrl);
        assertEquals(3, num.intValue());
        deltanum = CrlExtensions.getDeltaCRLIndicator(xcrl);
        assertEquals(2, deltanum.intValue());
        revcerts.add(new RevokedCertInfo(CertTools.getFingerprintAsString(usercert).getBytes(), CertTools.getSerialNumber(usercert).toByteArray(), revDate.getTime(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, CertTools.getNotAfter(usercert).getTime()));
        crl = x509ca.generateDeltaCRL(cryptoToken, revcerts, 4, 3);
        assertNotNull(crl);
        xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());
        deltanum = CrlExtensions.getDeltaCRLIndicator(xcrl);
        assertEquals(3, deltanum.intValue());
        set = xcrl.getRevokedCertificates();
        assertEquals(1, set.size());
        entry = (X509CRLEntry)set.iterator().next();
        assertEquals(CertTools.getSerialNumber(usercert).toString(), entry.getSerialNumber().toString());
        assertEquals(revDate.toString(), entry.getRevocationDate().toString());
        // Getting the revocation reason is a pita...
        extval = entry.getExtensionValue(Extension.reasonCode.getId());
        aIn = new ASN1InputStream(new ByteArrayInputStream(extval));
        octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        obj = aIn.readObject();
        reason = CRLReason.getInstance(obj);
        assertEquals("CRLReason: certificateHold", reason.toString());
	}



    /**
     * Tests the extension CRL Distribution Point on CRLs
     *
     */
	@Test
	public void testCRLDistPointOnCRL() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA ca = createTestCA(cryptoToken, CADN);

        final String cdpURL = "http://www.ejbca.org/foo/bar.crl";
        X509CAInfo cainfo = (X509CAInfo) ca.getCAInfo();

        cainfo.setUseCrlDistributionPointOnCrl(true);
        cainfo.setDefaultCRLDistPoint(cdpURL);
        ca.updateCA(cryptoToken, cainfo, cceConfig);

        Collection<RevokedCertInfo> revcerts = new ArrayList<RevokedCertInfo>();
        X509CRLHolder crl = ca.generateCRL(cryptoToken, revcerts, 1);
        assertNotNull(crl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());

        byte[] cdpDER = xcrl.getExtensionValue(Extension.issuingDistributionPoint.getId());
        assertNotNull("CRL has no distribution points", cdpDER);

        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(cdpDER));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        IssuingDistributionPoint cdp = IssuingDistributionPoint.getInstance(aIn.readObject());
        DistributionPointName distpoint = cdp.getDistributionPoint();

        assertEquals("CRL distribution point is different", cdpURL, ((DERIA5String) ((GeneralNames) distpoint.getName()).getNames()[0].getName()).getString());

        cainfo.setUseCrlDistributionPointOnCrl(false);
        cainfo.setDefaultCRLDistPoint(null);
        ca.updateCA(cryptoToken, cainfo, cceConfig);
        crl = ca.generateCRL(cryptoToken, revcerts, 1);
        assertNotNull(crl);
        xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());
        assertNull("CRL has distribution points", xcrl.getExtensionValue(Extension.cRLDistributionPoints.getId()));
    }

    /**
     * Tests the extension Freshest CRL DP.
     *
     * @throws Exception
     *             in case of error.
     */
	@Test
    public void testCRLFreshestCRL() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA ca = createTestCA(cryptoToken, CADN);
        final String cdpURL = "http://www.ejbca.org/foo/bar.crl";
        final String freshestCdpURL = "http://www.ejbca.org/foo/delta.crl";
        X509CAInfo cainfo = (X509CAInfo) ca.getCAInfo();

        cainfo.setUseCrlDistributionPointOnCrl(true);
        cainfo.setDefaultCRLDistPoint(cdpURL);
        cainfo.setCADefinedFreshestCRL(freshestCdpURL);
        ca.updateCA(cryptoToken, cainfo, cceConfig);

        Collection<RevokedCertInfo> revcerts = new ArrayList<RevokedCertInfo>();
        X509CRLHolder crl = ca.generateCRL(cryptoToken, revcerts, 1);
        assertNotNull(crl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());

        byte[] cFreshestDpDER = xcrl.getExtensionValue(Extension.freshestCRL.getId());
        assertNotNull("CRL has no Freshest Distribution Point", cFreshestDpDER);

        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(cFreshestDpDER));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        CRLDistPoint cdp = CRLDistPoint.getInstance(aIn.readObject());
        DistributionPoint[] distpoints = cdp.getDistributionPoints();

        assertEquals("More CRL Freshest distributions points than expected", 1, distpoints.length);
        assertEquals("Freshest CRL distribution point is different", freshestCdpURL, ((DERIA5String) ((GeneralNames) distpoints[0].getDistributionPoint()
                .getName()).getNames()[0].getName()).getString());

        cainfo.setUseCrlDistributionPointOnCrl(false);
        cainfo.setDefaultCRLDistPoint(null);
        cainfo.setCADefinedFreshestCRL(null);
        ca.updateCA(cryptoToken, cainfo, cceConfig);

        crl = ca.generateCRL(cryptoToken, revcerts, 1);
        assertNotNull(crl);
        xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());
        assertNull("CRL has freshest crl extension", xcrl.getExtensionValue(Extension.freshestCRL.getId()));
    }

	@Test
    public void testStoreAndLoadRSA() throws Exception {
	    doTestStoreAndLoad(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
    }

    @Test
    public void testStoreAndLoadGOST() throws Exception {
        assumeTrue(AlgorithmTools.isGost3410Enabled());
        doTestStoreAndLoad(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410);
    }

    @Test
    public void testStoreAndLoadDSTU() throws Exception {
        assumeTrue(AlgorithmTools.isDstu4145Enabled());
        doTestStoreAndLoad(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145);
    }

	private void doTestStoreAndLoad(String algName) throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
		final X509CA ca = createTestCA(cryptoToken, CADN, algName, null, null);

        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        KeyPair keypair = genTestKeyPair(algName);
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
        String authKeyId = new String(Hex.encode(CertTools.getAuthorityKeyId(usercert)));
        String keyhash = CertTools.getFingerprintAsString(cryptoToken.getPublicKey(ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)).getEncoded());

        // Save CA data
		Object o = ca.saveData();

		// Restore CA from data (and other things)
		@SuppressWarnings({ "rawtypes", "unchecked" })
        X509CA ca1 = new X509CA((HashMap)o, 777, CADN, "test", CAConstants.CA_ACTIVE, new Date(), new Date());

		Certificate usercert1 = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);

        String authKeyId1 = new String(Hex.encode(CertTools.getAuthorityKeyId(usercert1)));
        PublicKey publicKey1 = cryptoToken.getPublicKey(ca1.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        String keyhash1 = CertTools.getFingerprintAsString(publicKey1.getEncoded());
        assertEquals(authKeyId, authKeyId1);
        assertEquals(keyhash, keyhash1);

        CAInfo cainfo = ca.getCAInfo();
        CAData cadata = new CAData(cainfo.getSubjectDN(), cainfo.getName(), cainfo.getStatus(), ca);

        CA ca2 = cadata.getCA();
		Certificate usercert2 = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
        String authKeyId2 = new String(Hex.encode(CertTools.getAuthorityKeyId(usercert2)));
        PublicKey publicKey2 = cryptoToken.getPublicKey(ca2.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        String keyhash2 = CertTools.getFingerprintAsString(publicKey2.getEncoded());
        assertEquals(authKeyId, authKeyId2);
        assertEquals(keyhash, keyhash2);

        // Check CAinfo and CAtokeninfo
        final CAInfo cainfo1 = ca.getCAInfo();
        final CAToken caToken1 = cainfo1.getCAToken();
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, caToken1.getSignatureAlgorithm());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, caToken1.getEncryptionAlgorithm());
        assertEquals(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, caToken1.getKeySequenceFormat());

        final CAInfo cainfo2 = ca2.getCAInfo();
        final CAToken caToken2 = cainfo2.getCAToken();
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, caToken2.getSignatureAlgorithm());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, caToken2.getEncryptionAlgorithm());
        assertEquals(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, caToken2.getKeySequenceFormat());
	}

	@Test
	public void testExtendedCAServices() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
		final X509CA ca = createTestCA(cryptoToken, CADN);
		assertEquals(ca.getExternalCAServiceTypes().size(), 0);
		assertNull(ca.getExtendedCAServiceInfo(1));

		CAInfo info = ca.getCAInfo();
		Collection<ExtendedCAServiceInfo> infos = new ArrayList<ExtendedCAServiceInfo>();
		infos.add(new MyExtendedCAServiceInfo(0));
		info.setExtendedCAServiceInfos(infos);
		ca.updateCA(cryptoToken, info, cceConfig);

		assertEquals(ca.getExternalCAServiceTypes().size(), 1);
		assertNotNull(ca.getExtendedCAServiceInfo(4711));
		assertNull(ca.getExtendedCAServiceInfo(1));
		assertNotNull("org.cesecore.certificates.ca.MyExtendedCAServiceInfo", ca.getExtendedCAServiceInfo(4711).getClass().getName());

		// Try to run it
		assertEquals(0, MyExtendedCAService.didrun);
		ca.extendedService(cryptoToken, new MyExtendedCAServiceRequest());
		assertEquals(1, MyExtendedCAService.didrun);
		ca.extendedService(cryptoToken, new MyExtendedCAServiceRequest());
		assertEquals(2, MyExtendedCAService.didrun);

		// Does is store and load ok?
		Object o = ca.saveData();
		// Restore CA from data (and other things)
		@SuppressWarnings({ "rawtypes", "unchecked" })
        X509CA ca1 = new X509CA((HashMap)o, 777, CADN, "test", CAConstants.CA_ACTIVE, new Date(), new Date());
		ca1.extendedService(cryptoToken, new MyExtendedCAServiceRequest());
		assertEquals(3, MyExtendedCAService.didrun);
	}

	@Test
	public void testCAInfo() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
		X509CA ca = createTestCA(cryptoToken, CADN);
		assertEquals(CAConstants.CA_ACTIVE, ca.getStatus());
		assertEquals(CAConstants.CA_ACTIVE, ca.getCAInfo().getStatus());
		ca.setStatus(CAConstants.CA_OFFLINE);
		assertEquals(CAConstants.CA_OFFLINE, ca.getStatus());
		assertEquals(CAConstants.CA_OFFLINE, ca.getCAInfo().getStatus());
	}

    /**
     * Swaps two GeneralName items in a GeneralNames object.
     * @param gns The GeneralNames object. Will not be modified.
     * @param index1 Index of one item to swap.
     * @param index2 Index of the other item to swap.
     * @return New GeneralName object, with items swapped.
     */
    private GeneralNames swapGeneralNames(final GeneralNames gns, final int index1, final int index2) {
        final GeneralName[] arr = gns.getNames();
        final GeneralName tmp = arr[index1];
        arr[index1] = arr[index2];
        arr[index2] = tmp;
        return new GeneralNames(arr);
    }

	@Test
	public void testCTRedactedLabels() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA ca = createTestCA(cryptoToken, CADN);
        GeneralNames gns = CertTools.getGeneralNamesFromAltName("rfc822Name=foo@bar.com,dnsName=foo.bar.com,dnsName=(hidden).secret.se,dnsName=(hidden1).(hidden2).ultrasecret.no,directoryName=cn=Tomas\\,O=PrimeKey\\,C=SE,iPAddress=192.0.2.123");
        gns = swapGeneralNames(gns, 0, 5); // Swap iPAddress and rfc822Name to test that the order is preserved
	    Extension ext = new Extension(Extension.subjectAlternativeName, false, gns.toASN1Primitive().getEncoded(ASN1Encoding.DER));
	    ExtensionsGenerator gen = ca.getSubjectAltNameExtensionForCert(ext, false);
	    Extensions exts = gen.generate();
	    Extension genext = exts.getExtension(Extension.subjectAlternativeName);
        Extension ctext = exts.getExtension(new ASN1ObjectIdentifier(CertTools.id_ct_redacted_domains));
	    assertNotNull("A subjectAltName extension should be present", genext);
	    assertNull("No CT redated extension should be present", ctext);
        String altName = CertTools.getAltNameStringFromExtension(genext);
        assertEquals("altName is not what it should be", "iPAddress=192.0.2.123, dNSName=foo.bar.com, dNSName=hidden.secret.se, dNSName=hidden1.hidden2.ultrasecret.no, directoryName=CN=Tomas\\,O=PrimeKey\\,C=SE, rfc822name=foo@bar.com", altName);
	    // Test with CT publishing
	    gen = ca.getSubjectAltNameExtensionForCert(ext, true);
	    exts = gen.generate();
	    genext = exts.getExtension(Extension.subjectAlternativeName);
	    ctext = exts.getExtension(new ASN1ObjectIdentifier(CertTools.id_ct_redacted_domains));
	    assertNotNull("A subjectAltName extension should be present", genext);
	    assertNotNull("A CT redacted extension should be present", ctext);
        ASN1Sequence seq = ASN1Sequence.getInstance(ctext.getExtnValue().getOctets());
        assertEquals("should be three dnsNames", 3, seq.size());
        ASN1Integer derInt = ASN1Integer.getInstance(seq.getObjectAt(0));
        assertEquals("first dnsName should have 0 redacted labels", 0, derInt.getValue().intValue());
        derInt = ASN1Integer.getInstance(seq.getObjectAt(1));
        assertEquals("second dnsName should have 1 redacted labels", 1, derInt.getValue().intValue());
        derInt = ASN1Integer.getInstance(seq.getObjectAt(2));
        assertEquals("third dnsName should have 2 redacted labels", 2, derInt.getValue().intValue());
        altName = CertTools.getAltNameStringFromExtension(genext);
        assertEquals("altName is not what it should be", "iPAddress=192.0.2.123, dNSName=foo.bar.com, dNSName=hidden.secret.se, dNSName=hidden1.hidden2.ultrasecret.no, directoryName=CN=Tomas\\,O=PrimeKey\\,C=SE, rfc822name=foo@bar.com", altName);
	}

    @Test
    public void testCTRedactedLabelsInPreCert() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA ca = createTestCA(cryptoToken, CADN);
        GeneralNames gns = CertTools.getGeneralNamesFromAltName("rfc822Name=foo@bar.com,iPAddress=192.0.2.123,dnsName=foo.bar.com,dnsName=(hidden).secret.se,dnsName=(hidden1).(hidden2).ultrasecret.no,directoryName=cn=Tomas\\,O=PrimeKey\\,C=SE");
        gns = swapGeneralNames(gns, 0, 5); // Swap iPAddress and rfc822Name to test that the order is preserved
        Extension ext = new Extension(Extension.subjectAlternativeName, false, gns.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        ExtensionsGenerator gen = ca.getSubjectAltNameExtensionForCTCert(ext);
        Extensions exts = gen.generate();
        Extension genext = exts.getExtension(Extension.subjectAlternativeName);
        Extension ctext = exts.getExtension(new ASN1ObjectIdentifier(CertTools.id_ct_redacted_domains));
        assertNotNull("A subjectAltName extension should be present", genext);
        assertNull("No CT redated extension should be present", ctext);
        String altName = CertTools.getAltNameStringFromExtension(genext);
        assertEquals("altName is not what it should be", "iPAddress=192.0.2.123, dNSName=foo.bar.com, dNSName=(PRIVATE).secret.se, dNSName=(PRIVATE).ultrasecret.no, directoryName=CN=Tomas\\,O=PrimeKey\\,C=SE, rfc822name=foo@bar.com", altName);
    }

	@Test
	public void testInvalidSignatureAlg() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
		try {
			createTestCA(cryptoToken, CADN, "MD5WithRSA", null, null);
			fail("This should throw because md5withRSA is not an allowed signature algorithm. It is vulnerable.");
		} catch (InvalidAlgorithmException e) {
			// NOPMD: this is what we want
		}
		X509CA ca = createTestCA(cryptoToken, CADN, "SHA1WithRSA", null, null);
		assertNotNull("should work to create a CA", ca);
		CAToken token = new CAToken(0, new Properties());
		ca.setCAToken(token);
	}

	@Test
    public void testWrongCAKeyRSA() throws Exception {
        doTestWrongCAKey(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
    }

    @Test
    public void testWrongCAKeyGOST() throws Exception {
        assumeTrue(AlgorithmTools.isGost3410Enabled());
        doTestWrongCAKey(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410);
    }

	@Test
    public void testWrongCAKeyDSTU() throws Exception {
        assumeTrue(AlgorithmTools.isDstu4145Enabled());
        doTestWrongCAKey(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145);
    }

	public void doTestWrongCAKey(String algName) throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
	    X509CA x509ca = createTestCA(cryptoToken, CADN, algName, null, null);

	    // Generate a client certificate and check that it was generated correctly
	    EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
	    KeyPair keypair = genTestKeyPair(algName);
	    CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
	    cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
	    cp.setUseCertificatePolicies(true);
	    Certificate usercert = x509ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
	    assertNotNull(usercert);

	    // Change CA keys, but not CA certificate, should not work to issue a certificate with this CA, when the
	    // issued cert can not be verified by the CA certificate
        cryptoToken.generateKeyPair(getTestKeySpec(algName), CAToken.SOFTPRIVATESIGNKEYALIAS);

	    try {
	        usercert = x509ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
	        fail("should not work to issue this certificate");
	    } catch (SignatureException e) {} // NOPMD: BC 1.47
        try {
            Collection<RevokedCertInfo> revcerts = new ArrayList<RevokedCertInfo>();
            x509ca.generateCRL(cryptoToken, revcerts, 1);
            fail("should not work to issue this CRL");
        } catch (SignatureException e) {
            // NOPMD: this is what we want
        }

	    // New CA certificate to make it work again
        PublicKey publicKey = cryptoToken.getPublicKey(x509ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        PrivateKey privateKey = cryptoToken.getPrivateKey(x509ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        X509Certificate cacert = CertTools.genSelfCert(CADN, 10L, "1.1.1.1", privateKey, publicKey, "SHA256WithRSA", true);
	    assertNotNull(cacert);
        List<Certificate> cachain = new ArrayList<Certificate>();
	    cachain.add(cacert);
	    x509ca.setCertificateChain(cachain);
        usercert = x509ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
        assertNotNull(usercert);
        Collection<RevokedCertInfo> revcerts = new ArrayList<RevokedCertInfo>();
        X509CRLHolder crl = x509ca.generateCRL(cryptoToken, revcerts, 1);
        assertNotNull(crl);
	}

	   /** Test implementation of Authority Information Access CRL Extension according to RFC 4325 */
    @Test
    public void testRfc822NameWithPlus() throws Exception {

        // set up test CA, end entity and certificate profile
        final CryptoToken cryptoToken = getNewCryptoToken();
        final KeyPair keypair = KeyTools.genKeys("1024", "RSA");
        final X509CA ca = createTestCA(cryptoToken, "CN=foo");

        String emailPlain = "user@user.com";
        String emailEscaped = "user\\+plus@user.com";
        String emailUnescaped = "user+plus@user.com";
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

        // test with no plus character in email
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=" + emailPlain, emailPlain,
                new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        Certificate certificate = null;
        try {
            certificate = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", profile, "00000", cceConfig);
            assertNotNull(certificate);
            assertEquals("rfc822name=" + emailPlain, CertTools.getSubjectAlternativeName(certificate));
        } catch (CAOfflineException e) {
            fail("Certificate could not be created or AIA could not be parsed: " + e.getMessage());
        }

        // test with a user with escaped plus character in email
        user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=" + emailEscaped, emailEscaped,
                new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        try {
            certificate = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", profile, "00000", cceConfig);
            assertNotNull(certificate);
            // getSubjectAlternativeName performs escaping again
            assertEquals("rfc822name=" + emailEscaped, CertTools.getSubjectAlternativeName(certificate));
        } catch (CAOfflineException e) {
            fail("Certificate could not be created or AIA could not be parsed: " + e.getMessage());
        }

        // test with a user with unescaped plus character in email
        user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=" + emailUnescaped, emailUnescaped,
                new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        try {
            certificate = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", profile, "00000", cceConfig);
            assertNotNull(certificate);
            // An unescaped '+' character is interpreted as a separator between two connected subjectAltName fields. So "rfc822Name=user+plus@user.com" is
            // handled as "rfc822Name=user" and "plus@user.com". Since the second part does not map to any known fields, the resulting SubjectAltName is
            // "rfc822Name=user"
            assertFalse(StringUtils.equals("rfc822name=" + emailUnescaped, CertTools.getSubjectAlternativeName(certificate)));
            assertFalse(StringUtils.equals("rfc822name=" + emailEscaped, CertTools.getSubjectAlternativeName(certificate)));
            assertEquals("rfc822name=user", CertTools.getSubjectAlternativeName(certificate));
        } catch (CAOfflineException e) {
            fail("Certificate could not be created: " + e.getMessage());
        }
    }

	/** Test implementation of Authority Information Access CRL Extension according to RFC 4325 */
    @Test
    public void testAuthorityInformationAccessCertificateExtension() throws Exception {
        // test data for CA - level
        final List<String> caIssuerUris = new ArrayList<String>();
        caIssuerUris.add( "http://ca-defined.ca.issuer.uri1.sw");
        caIssuerUris.add( "http://ca-defined.ca.issuer.uri2.sw");
        final List<String> ocspUrls = new ArrayList<String>();
        ocspUrls.add("http://ca-defined.ocsp.service.locator.url.sw");
        // test data for certificate profile - level
        final List<String> cpCaIssuerUris = new ArrayList<String>();
        cpCaIssuerUris.add( "http://certificate-profile.ca.issuer.uri1.sw");
        cpCaIssuerUris.add( "http://certificate-profile.ca.issuer.uri2.sw");
        final List<String> cpOcspUrls = new ArrayList<String>();
        cpOcspUrls.add("http://certificate-profile.ocsp.service.locator.url.sw");
        // set up test CA, end entity and certificate profile
        final CryptoToken cryptoToken = getNewCryptoToken();
        final KeyPair keypair = KeyTools.genKeys("1024", "RSA");
        final X509CA ca = createTestCA(cryptoToken, "CN=foo");
        final EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        final CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setUseAuthorityInformationAccess(true); // enable certificate AIA
        Certificate certificate = null;

        // 1. test with all values filled and both 'Use CA defined' switches are true
        ca.setCertificateAiaDefaultCaIssuerUri(caIssuerUris);
        ca.setDefaultOCSPServiceLocator(ocspUrls.get(0));
        profile.setCaIssuers(cpCaIssuerUris);
        profile.setOCSPServiceLocatorURI(cpOcspUrls.get(0));
        profile.setUseDefaultCAIssuer(true);
        profile.setUseDefaultOCSPServiceLocator(true);
        try {
            certificate = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", profile, "00000", cceConfig);
            assertCertificateAuthorityInformationAccess( certificate, caIssuerUris, ocspUrls);
        } catch (CAOfflineException e) {
            fail("Certificate could not be created or AIA could not be parsed: " + e.getMessage());
        }

        // 2. test with all values filled and both 'Use CA defined' switches are false
        profile.setUseDefaultCAIssuer(false);
        profile.setUseDefaultOCSPServiceLocator(false);
        try {
            certificate = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", profile, "00000", cceConfig);
            assertCertificateAuthorityInformationAccess( certificate, cpCaIssuerUris, cpOcspUrls);
        } catch (CAOfflineException e) {
            fail("Certificate could not be created or AIA could not be parsed: " + e.getMessage());
        }

        // 3a. test with all values filled and 'Use CA defined' CA issuer switch true, the other false,
        profile.setUseDefaultCAIssuer(true);
        profile.setUseDefaultOCSPServiceLocator(false);
        try {
            certificate = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", profile, "00000", cceConfig);
            assertCertificateAuthorityInformationAccess( certificate, caIssuerUris, cpOcspUrls);
        } catch (CAOfflineException e) {
            fail("Certificate could not be created or AIA could not be parsed: " + e.getMessage());
        }

        // 3b. test with all values filled and 'Use CA defined' OCSP service switch true, the other false,
        profile.setUseDefaultCAIssuer(false);
        profile.setUseDefaultOCSPServiceLocator(true);
        try {
            certificate = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", profile, "00000", cceConfig);
            assertCertificateAuthorityInformationAccess( certificate, cpCaIssuerUris, ocspUrls);
        } catch (CAOfflineException e) {
            fail("Certificate could not be created or AIA could not be parsed: " + e.getMessage());
        }
    }

    private final void assertCertificateAuthorityInformationAccess(Certificate certificate, List<String> caIssuerUris, List<String> ocspUrls) {
        List<String> testList = CertTools.getAuthorityInformationAccessCAIssuerUris(certificate);
        assertTrue("Certificate CA issuer URIs " + Arrays.toString(caIssuerUris.toArray()) + " expected but was " + Arrays.toString(testList.toArray()), caIssuerUris.equals(testList));
        testList = CertTools.getAuthorityInformationAccessOcspUrls(certificate);
        assertTrue("Certificate OCSP service locators " + Arrays.toString(ocspUrls.toArray()) + " expected but was " + Arrays.toString(testList.toArray()), ocspUrls.equals(testList));
    }


	/** Test implementation of Authority Information Access CRL Extension according to RFC 4325 */
	@Test
	public void testAuthorityInformationAccessCrlExtension() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
	    X509CA testCa = createTestCA(cryptoToken, "CN=foo");
	    List<String> authorityInformationAccess = new ArrayList<String>();
	    authorityInformationAccess.add("http://example.com/0");
	    authorityInformationAccess.add("http://example.com/1");
	    authorityInformationAccess.add("http://example.com/2");
	    authorityInformationAccess.add("http://example.com/3");
	    testCa.setAuthorityInformationAccess(authorityInformationAccess);
	    Collection<RevokedCertInfo> revcerts = new ArrayList<RevokedCertInfo>();
	    X509CRLHolder testCrl = testCa.generateCRL(cryptoToken, revcerts, 0);
        assertNotNull(testCrl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(testCrl.getEncoded());
	    Collection<String> result = CertTools.getAuthorityInformationAccess(xcrl);
	    assertEquals("Number of URLs do not match", authorityInformationAccess.size(), result.size());
	    for(String url : authorityInformationAccess) {
	        if(!result.contains(url)) {
	            fail("URL " + url + " was not found.");
	        }
	    }
	}

	/** Test implementation of Authority Information Access CRL Extension according to RFC 4325 */
    @Test
    public void testAuthorityInformationAccessCrlExtensionWithEmptyList() throws Exception{
        final CryptoToken cryptoToken = getNewCryptoToken();
        X509CA testCa = createTestCA(cryptoToken, "CN=foo");
        Collection<RevokedCertInfo> revcerts = new ArrayList<RevokedCertInfo>();
        X509CRLHolder testCrl = testCa.generateCRL(cryptoToken, revcerts, 0);
        assertNotNull(testCrl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(testCrl.getEncoded());
        Collection<String> result = CertTools.getAuthorityInformationAccess(xcrl);
        assertEquals("A list was returned without any values present.", 0, result.size());
    }

    /**
     * Test that the CA refuses to issue certificates outside of the PrivateKeyUsagePeriod, but that it does issue a cert within this period.
     * This test has some timing, so it sleeps in total 11 seconds during the test.
     */
    @Test
    public void testCAPrivateKeyUsagePeriodRequest() throws Exception {
        // User keypair, generate first so it will not take any seconds from the timing test below
        final KeyPair keypair = KeyTools.genKeys("512", "RSA");
        // Create a new CA with private key usage period
        final CryptoToken cryptoToken = getNewCryptoToken();
        Calendar notBefore = Calendar.getInstance();
        notBefore.add(Calendar.SECOND, 5); // 5 seconds in the future
        Calendar notAfter = Calendar.getInstance();
        notAfter.add(Calendar.SECOND, 10); // 10 seconds in the future gives us a 5 second window to generate a cert
        X509CA testCa = createTestCA(cryptoToken, "CN=foo", "SHA256WithRSA", notBefore.getTime(), notAfter.getTime());
        // Issue a certificate before PrivateKeyUsagePeriod has started to be valid
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        try {
            testCa.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
            fail("Should throw CAOfflineException when trying to issue cert before PrivateKeyUsagePeriod starts.");
        } catch (CAOfflineException e) {
            // NOPMD: this is what we expect
        }
        // Issue a certificate within private key usage period
        // Sleep 6 seconds, now it should work
        Thread.sleep(6000);
        try {
            Certificate cert = testCa.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
            assertNotNull("A certificate should have been issued", cert);
        } catch (CAOfflineException e) {
            fail("Should not throw CAOfflineException when issuing a certificate within PrivateKeyUsagePeriod.");
        }
        // Issue a certificate after private key usage period expires
        // Sleep 5 seconds, now it should not work again since PrivateKeyUsagePeriod has expired
        Thread.sleep(5000);
        try {
            testCa.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
            fail("Should throw CAOfflineException when trying to issue cert after PrivateKeyUsagePeriod ands.");
        } catch (CAOfflineException e) {
            // NOPMD: this is what we expect
        }
    }

    /**
     * Test that the CA can issue certificates with custom certificate extensions.
     */
    @Test
    public void testCustomCertificateExtension() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        X509CA testCa = createTestCA(cryptoToken, "CN=foo");
        Collection<RevokedCertInfo> revcerts = new ArrayList<RevokedCertInfo>();
        X509CRLHolder testCrl = testCa.generateCRL(cryptoToken, revcerts, 0);
        assertNotNull(testCrl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(testCrl.getEncoded());
        Collection<String> result = CertTools.getAuthorityInformationAccess(xcrl);
        assertEquals("A list was returned without any values present.", 0, result.size());
        // Issue a certificate with two different basic certificate extensions
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com,dnsName=foo.bar.com,directoryName=CN=Tomas\\,O=PrimeKey\\,C=SE", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        // Configure some custom basic certificate extension
        // one with a good IA5String encoding
        Properties props1 = new Properties();
        props1.put("used", "true");
        props1.put("encoding", "DERIA5STRING");
        props1.put("dynamin", "false");
        props1.put("value", "Hello World");
        cceConfig.addCustomCertExtension(1, "2.16.840.1.113730.1.13", "NetscapeComment", "org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension", false, true, props1);

        // one RAW with proper DER encoding
        Properties props2 = new Properties();
        props2.put("used", "true");
        props2.put("encoding", "RAW");
        props2.put("dynamin", "false");
        props2.put("value", "301a300c060a2b060104018237140202300a06082b06010505070302");
        cceConfig.addCustomCertExtension(2, "1.2.3.4", "RawProper", "org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension", false, true, props2);

        // one RAW with no DER encoding (actually invalid according to RFC5280)
        Properties props3 = new Properties();
        props3.put("used", "true");
        props3.put("encoding", "RAW");
        props3.put("dynamin", "false");
        props3.put("value", "aabbccddeeff00");
        cceConfig.addCustomCertExtension(3, "1.2.3.5", "RawNoDer", "org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension", false, true, props3);

        assertEquals(cceConfig.getCustomCertificateExtension(1).getOID(), "2.16.840.1.113730.1.13");
        assertEquals(cceConfig.getCustomCertificateExtension(2).getOID(), "1.2.3.4");
        assertEquals(cceConfig.getCustomCertificateExtension(3).getOID(), "1.2.3.5");
        // Configure to use the custom extensions in the certificate profile
        List<Integer> list = new ArrayList<Integer>();
        list.add(1);
        list.add(2);
        list.add(3);
        cp.setUsedCertificateExtensions(list);
        final KeyPair keypair = KeyTools.genKeys("512", "RSA");
        X509Certificate cert = (X509Certificate)testCa.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
        assertNotNull("A certificate should have been issued", cert);
        byte[] ext1 = cert.getExtensionValue("2.16.840.1.113730.1.13");
        // The Extension value is an Octet String, containing my value
        ASN1InputStream is = new ASN1InputStream(ext1);
        ASN1OctetString oct = (ASN1OctetString) (is.readObject());
        is.close();
        ASN1InputStream is2 = new ASN1InputStream(oct.getOctets());
        DERIA5String str = (DERIA5String)is2.readObject();
        is2.close();
        assertEquals("Hello World", str.getString());

        byte[] ext2 = cert.getExtensionValue("1.2.3.4");
        is = new ASN1InputStream(ext2);
        oct = (ASN1OctetString) (is.readObject());
        is.close();
        is2 = new ASN1InputStream(oct.getOctets());
        ASN1Sequence seq = (ASN1Sequence)is2.readObject();
        System.out.println(ASN1Dump.dumpAsString(seq));
        is2.close();
        ASN1Encodable enc = seq.getObjectAt(0);
        ASN1Sequence seq2 = ASN1Sequence.getInstance(enc);
        ASN1Encodable enc2 = seq2.getObjectAt(0);
        ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(enc2);
        assertEquals("1.3.6.1.4.1.311.20.2.2", id.getId());
        enc = seq.getObjectAt(1);
        seq2 = ASN1Sequence.getInstance(enc);
        enc2 = seq2.getObjectAt(0);
        id = ASN1ObjectIdentifier.getInstance(enc2);
        assertEquals("1.3.6.1.5.5.7.3.2", id.getId());

        byte[] ext3 = cert.getExtensionValue("1.2.3.5");
        is = new ASN1InputStream(ext3);
        oct = (ASN1OctetString) (is.readObject());
        is.close();
        // This value can not be parsed as ASN.1
        byte[] bytes = oct.getOctets();
        assertEquals("aabbccddeeff00", Hex.toHexString(bytes));
    }

    /** Tests encoding of Certificate Policy extensions
     */
    @Test
    public void testCertificatePolicyExtension() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        final String caDN = "CN=Text CertificatePolicy Extension";
        final X509CA testCa = createTestCA(cryptoToken, caDN);

        // Generate cert by calling generateCertificate directly
        Certificate cacert = testCa.getCACertificate(); // yeah, we just need to get a public key really fast
        final String subjectDN = "CN=cert policy extension test";
        final EndEntityInformation subject = new EndEntityInformation("cert policy extension test", subjectDN, testCa.getCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        final CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        CertificatePolicy cp1 = new CertificatePolicy("1.1.1.2", PolicyQualifierId.id_qt_cps.getId(), "https://ejbca.org/2");
        CertificatePolicy cp2 = new CertificatePolicy("1.1.1.3", PolicyQualifierId.id_qt_cps.getId(), "https://ejbca.org/3");
        CertificatePolicy cp3 = new CertificatePolicy("1.1.1.1", null, null);
        CertificatePolicy cp4 = new CertificatePolicy("1.1.1.4", PolicyQualifierId.id_qt_unotice.getId(), "My User Notice Text");
        CertificatePolicy cp5 = new CertificatePolicy("1.1.1.5", PolicyQualifierId.id_qt_unotice.getId(), "EJBCA User Notice");
        CertificatePolicy cp6 = new CertificatePolicy("1.1.1.5", PolicyQualifierId.id_qt_cps.getId(), "https://ejbca.org/CPS");
        certProfile.addCertificatePolicy(cp1);
        certProfile.addCertificatePolicy(cp2);
        certProfile.addCertificatePolicy(cp3);
        certProfile.addCertificatePolicy(cp4);
        certProfile.addCertificatePolicy(cp5);
        certProfile.addCertificatePolicy(cp6);
        certProfile.setUseCertificatePolicies(true);
        Certificate cert = testCa.generateCertificate(cryptoToken, subject, cacert.getPublicKey(), KeyUsage.digitalSignature | KeyUsage.keyEncipherment, null, "30d", certProfile, null, cceConfig);
        // Get the full policy objects
        List<PolicyInformation> pi = CertTools.getCertificatePolicies(cert);
        assertEquals("Should be 5 Cert Policies", 5, pi.size());
        assertEquals("1.1.1.2", pi.get(0).getPolicyIdentifier().getId());
        assertEquals("1.1.1.3", pi.get(1).getPolicyIdentifier().getId());
        assertEquals("1.1.1.1", pi.get(2).getPolicyIdentifier().getId());
        assertEquals("1.1.1.4", pi.get(3).getPolicyIdentifier().getId());
        assertEquals("1.1.1.5", pi.get(4).getPolicyIdentifier().getId());

        // The first Policy object has a CPS URI
        ASN1Encodable qualifier = pi.get(0).getPolicyQualifiers().getObjectAt(0);
        PolicyQualifierInfo pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_cps = 1.3.6.1.5.5.7.2.1
        assertEquals(PolicyQualifierId.id_qt_cps.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_cps, we know this is a DERIA5String
        DERIA5String str = DERIA5String.getInstance(pqi.getQualifier());
        assertEquals("https://ejbca.org/2", str.getString());

        // The second Policy object has a CPS URI
        qualifier = pi.get(1).getPolicyQualifiers().getObjectAt(0);
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_cps = 1.3.6.1.5.5.7.2.1
        assertEquals(PolicyQualifierId.id_qt_cps.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_cps, we know this is a DERIA5String
        str = DERIA5String.getInstance(pqi.getQualifier());
        assertEquals("https://ejbca.org/3", str.getString());

        // The third Policy object has only an OID
        qualifier = pi.get(2).getPolicyQualifiers();
        assertNull(qualifier);

        // The fourth Policy object has a User Notice
        qualifier = pi.get(3).getPolicyQualifiers().getObjectAt(0);
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_unotice = 1.3.6.1.5.5.7.2.2
        assertEquals(PolicyQualifierId.id_qt_unotice.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_unutice, we know this is a UserNotice
        UserNotice un = UserNotice.getInstance(pqi.getQualifier());
        assertEquals("My User Notice Text", un.getExplicitText().getString());

        // The fifth Policy object has both a CPS URI and a User Notice
        qualifier = pi.get(4).getPolicyQualifiers().getObjectAt(0);
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_unotice = 1.3.6.1.5.5.7.2.2
        assertEquals(PolicyQualifierId.id_qt_unotice.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_unutice, we know this is a UserNotice
        un = UserNotice.getInstance(pqi.getQualifier());
        assertEquals("EJBCA User Notice", un.getExplicitText().getString());
        qualifier = pi.get(4).getPolicyQualifiers().getObjectAt(1);
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_cps = 1.3.6.1.5.5.7.2.1
        assertEquals(PolicyQualifierId.id_qt_cps.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_cps, we know this is a DERIA5String
        str = DERIA5String.getInstance(pqi.getQualifier());
        assertEquals("https://ejbca.org/CPS", str.getString());

    }

    /**
     * Tests default value of "use printable string" option (should be disabled by default)
     * and tests that the option works.
     */
    @Test
    public void testPrintableString() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        final String caDN = "CN=foo CA,O=Bar,JurisdictionCountry=DE,JurisdictionState=Stockholm,JurisdictionLocality=Solna,C=SE";
        final X509CA testCa = createTestCA(cryptoToken, caDN);
        assertFalse("\"Use Printable String\" should be turned off by default", testCa.getUsePrintableStringSubjectDN());

        Certificate cert = testCa.getCACertificate();
        assertTrue("Certificate CN was not UTF-8 encoded by default.", getValueFromDN(cert, X509ObjectIdentifiers.commonName) instanceof DERUTF8String);
        assertTrue("Certificate C was not PrintableString encoded.", getValueFromDN(cert, X509ObjectIdentifiers.countryName) instanceof DERPrintableString); // C is always PrintableString

        // Test generation by calling generateCertificate directly
        final String subjectDN = "CN=foo subject,O=Bar,JurisdictionCountry=DE,JurisdictionState=Stockholm,JurisdictionLocality=Solna,C=SE";
        final EndEntityInformation subject = new EndEntityInformation("testPrintableString", subjectDN, testCa.getCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        final CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cert = testCa.generateCertificate(cryptoToken, subject, cert.getPublicKey(), KeyUsage.digitalSignature | KeyUsage.keyEncipherment, null, "30d", certProfile, null, cceConfig);
        assertTrue("Certificate CN was not UTF-8 encoded by default.", getValueFromDN(cert, X509ObjectIdentifiers.commonName) instanceof DERUTF8String);
        assertTrue("Certificate O was not UTF-8 encoded by default.", getValueFromDN(cert, X509ObjectIdentifiers.organization) instanceof DERUTF8String);
        assertTrue("Certificate JurisdictionState was not UTF-8 encoded.", getValueFromDN(cert, CeSecoreNameStyle.JURISDICTION_STATE) instanceof DERUTF8String);
        assertTrue("Certificate JurisdictionLocality was not UTF-8 encoded.", getValueFromDN(cert, CeSecoreNameStyle.JURISDICTION_LOCALITY) instanceof DERUTF8String);
        assertTrue("Certificate C was not PrintableString encoded.", getValueFromDN(cert, X509ObjectIdentifiers.countryName) instanceof DERPrintableString); // C is always PrintableString
        assertTrue("Certificate JurisdictionCountry was not PrintableString encoded.", getValueFromDN(cert, CeSecoreNameStyle.JURISDICTION_COUNTRY) instanceof DERPrintableString); // C is always PrintableString

        // Now generate a new certificate with a PrintableString-encoded DN
        testCa.setUsePrintableStringSubjectDN(true);
        cert = testCa.generateCertificate(cryptoToken, subject, cert.getPublicKey(), KeyUsage.digitalSignature | KeyUsage.keyEncipherment, null, "30d", certProfile, null, cceConfig);
        assertTrue("Certificate CN was not encoded as PrintableString.", getValueFromDN(cert, X509ObjectIdentifiers.commonName) instanceof DERPrintableString);
        assertTrue("Certificate O was not encoded as PrintableString.", getValueFromDN(cert, X509ObjectIdentifiers.organization) instanceof DERPrintableString);
        assertTrue("Certificate JurisdictionState was not encoded as PrintableString.", getValueFromDN(cert, CeSecoreNameStyle.JURISDICTION_STATE) instanceof DERPrintableString);
        assertTrue("Certificate JurisdictionLocality was not encoded as PrintableString.", getValueFromDN(cert, CeSecoreNameStyle.JURISDICTION_LOCALITY) instanceof DERPrintableString);
        assertTrue("Certificate C was not PrintableString encoded.", getValueFromDN(cert, X509ObjectIdentifiers.countryName) instanceof DERPrintableString); // C is always PrintableString
        assertTrue("Certificate JurisdictionCountry was not PrintableString encoded.", getValueFromDN(cert, CeSecoreNameStyle.JURISDICTION_COUNTRY) instanceof DERPrintableString); // C is always PrintableString
    }

    /**
     * Tests using different DN orders in issued certificates.
     */
    @Test
    public void testDNOrder() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        final String caDN = "CN=foo CA,O=Bar,JurisdictionCountry=DE,JurisdictionState=Stockholm,JurisdictionLocality=Solna,C=SE";
        final X509CA testCa = createTestCA(cryptoToken, caDN);
        Certificate cert = testCa.getCACertificate();
        X500Principal princ = ((X509Certificate) cert).getSubjectX500Principal();
        X500Name name = X500Name.getInstance(princ.getEncoded());
        // The EV DN components do not have names in standard java/BC
        assertEquals("Wrong DN name of Test CA", "1.3.6.1.4.1.311.60.2.1.3=DE,1.3.6.1.4.1.311.60.2.1.2=Stockholm,1.3.6.1.4.1.311.60.2.1.1=Solna,CN=foo CA,O=Bar,C=SE", name.toString());

        // Test generation by calling generateCertificate directly
        final String subjectDN = "JurisdictionCountry=NL,JurisdictionState=State,JurisdictionLocality=Åmål,BusinessCategory=Private Organization,CN=evssltest6.test.lan,SN=1234567890,OU=XY,O=MyOrg B.V.,L=Åmål,ST=Norrland,C=SE";
        final EndEntityInformation subject = new EndEntityInformation("testPrintableString", subjectDN, testCa.getCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        final CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cert = testCa.generateCertificate(cryptoToken, subject, cert.getPublicKey(), KeyUsage.digitalSignature | KeyUsage.keyEncipherment, null, "30d", certProfile, null, cceConfig);
        princ = ((X509Certificate) cert).getSubjectX500Principal();
        name = X500Name.getInstance(princ.getEncoded());
        // The EV DN components do not have names in standard java/BC. This is standard order where EV fields are before CN and in other respects ldap order
        String desiredDN = "1.3.6.1.4.1.311.60.2.1.3=NL,1.3.6.1.4.1.311.60.2.1.2=State,1.3.6.1.4.1.311.60.2.1.1=Åmål,BusinessCategory=Private Organization,CN=evssltest6.test.lan,SERIALNUMBER=1234567890,OU=XY,O=MyOrg B.V.,L=Åmål,ST=Norrland,C=SE";
        assertEquals("Wrong DN order of issued certificate", desiredDN, name.toString());
        // Now set a DN order where the EV fields (and serialnumber and businesscategory) comes before C and in other aspects are x500 order
        final ArrayList<String> order = new ArrayList<String>(Arrays.asList("jurisdictioncountry", "jurisdictionstate", "jurisdictionlocality","businesscategory","serialnumber","c","dc","st","l","o","ou","t","surname","initials","givenname","gn","sn","name","cn","uid","dn","email","e","emailaddress","unstructuredname","unstructuredaddress","postalcode","postaladdress","telephonenumber","pseudonym","street"));
        certProfile.setCustomDnOrder(order);
        certProfile.setUseCustomDnOrder(true);
        cert = testCa.generateCertificate(cryptoToken, subject, cert.getPublicKey(), KeyUsage.digitalSignature | KeyUsage.keyEncipherment, null, "30d", certProfile, null, cceConfig);
        princ = ((X509Certificate) cert).getSubjectX500Principal();
        name = X500Name.getInstance(princ.getEncoded());
        // The EV DN components do not have names in standard java/BC
        desiredDN = "1.3.6.1.4.1.311.60.2.1.3=NL,1.3.6.1.4.1.311.60.2.1.2=State,1.3.6.1.4.1.311.60.2.1.1=Åmål,BusinessCategory=Private Organization,SERIALNUMBER=1234567890,C=SE,ST=Norrland,L=Åmål,O=MyOrg B.V.,OU=XY,CN=evssltest6.test.lan";
        assertEquals("Wrong DN order of issued certificate", desiredDN, name.toString());
    }

    /**
     * Testing that DN override works.
     */
    @Test
    public void testDNOverride() throws Exception {
        final String algName = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA x509ca = createTestCA(cryptoToken, CADN, algName, null, null);
        X509Certificate cacert = (X509Certificate) x509ca.getCACertificate();

        // Create a pkcs10 certificate request
        KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        X500Name x509dn = CertTools.stringToBcX500Name("CN=Override,O=PrimeKey,C=SE");
        PKCS10CertificationRequest req = CertTools.genPKCS10CertificationRequest(algName, x509dn, keyPair.getPublic(), null, keyPair.getPrivate(), BouncyCastleProvider.PROVIDER_NAME);
        PKCS10RequestMessage p10msg = new PKCS10RequestMessage(new JcaPKCS10CertificationRequest(req));
        assertEquals("CN=Override,O=PrimeKey,C=SE", p10msg.getRequestDN());

        // Generate a client certificate and check that it was generated correctly
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, null, "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = x509ca.generateCertificate(cryptoToken, user, p10msg, keyPair.getPublic(), 0, null, null, cp, null, "00000", cceConfig);
        assertNotNull(usercert);
        assertEquals("CN=User", CertTools.getSubjectDN(usercert));
        assertEquals(CADN, CertTools.getIssuerDN(usercert));
        assertEquals(getTestKeyPairAlgName(algName).toUpperCase(), AlgorithmTools.getCertSignatureAlgorithmNameAsString(usercert).toUpperCase());
        assertEquals(new String(CertTools.getSubjectKeyId(cacert)), new String(CertTools.getAuthorityKeyId(usercert)));
        // Allow DN override
        cp.setAllowDNOverride(true);
        usercert = x509ca.generateCertificate(cryptoToken, user, p10msg, keyPair.getPublic(), 0, null, null, cp, null, "00000", cceConfig);
        assertNotNull(usercert);
        assertEquals("CN=Override,O=PrimeKey,C=SE", CertTools.getSubjectDN(usercert));
        assertEquals(CADN, CertTools.getIssuerDN(usercert));
        assertEquals(getTestKeyPairAlgName(algName).toUpperCase(), AlgorithmTools.getCertSignatureAlgorithmNameAsString(usercert).toUpperCase());
        assertEquals(new String(CertTools.getSubjectKeyId(cacert)), new String(CertTools.getAuthorityKeyId(usercert)));
    }


    /**
     * Testing generating certificate with public key from providedRequestMessage (providedPublicKey and endEntityInformation.extendedInformation.certificateRequest must be null).
     */
    @Test
    public void testGeneratingCertificateWithPublicKeyFromProvidedRequestMessage() throws Exception {
        final String algName = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA x509ca = createTestCA(cryptoToken, CADN, algName, null, null);

        // Create a pkcs10 certificate request (this algorithm will be used)
        KeyPair keyPair = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
        X500Name x509dn = CertTools.stringToBcX500Name("CN=RequestMessageCn,O=PrimeKey,C=SE");
        PKCS10CertificationRequest certificationRequest = CertTools.genPKCS10CertificationRequest(algName, x509dn, keyPair.getPublic(), null, keyPair.getPrivate(), BouncyCastleProvider.PROVIDER_NAME);
        PKCS10RequestMessage requestMessage = new PKCS10RequestMessage(new JcaPKCS10CertificationRequest(certificationRequest));
        assertEquals("CN=RequestMessageCn,O=PrimeKey,C=SE", requestMessage.getRequestDN());
        EndEntityInformation endEntityInformation = new EndEntityInformation("username", "CN=EndEntityInformationCn,O=PrimeKey,C=SE", 666, null, "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);

        //Create CP and generate certificate
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = x509ca.generateCertificate(cryptoToken, endEntityInformation, requestMessage, /*providedPublicKey=*/null, 0, null, null, cp, null, "00000", cceConfig);
        assertNotNull(usercert);

        assertEquals("2048", AlgorithmTools.getKeySpecification(usercert.getPublicKey()));
        assertEquals(AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmTools.getKeyAlgorithm(usercert.getPublicKey()));
    }

    /**
     * Testing that CSR algorithm is enforced from end entity information if there is one.
     */
    @Test
    public void testProvidedPublicKeyAlgorithmEnforcedOverOneFromProvidedRequestMessage() throws Exception {
        final String algName = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA x509ca = createTestCA(cryptoToken, CADN, algName, null, null);

        // Create a pkcs10 certificate request (the algorithm will be overriden)
        KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        X500Name x509dn = CertTools.stringToBcX500Name("CN=RequestMessageCn,O=PrimeKey,C=SE");
        PKCS10CertificationRequest certificationRequest = CertTools.genPKCS10CertificationRequest(algName, x509dn, keyPair.getPublic(), null, keyPair.getPrivate(), BouncyCastleProvider.PROVIDER_NAME);
        PKCS10RequestMessage requestMessage = new PKCS10RequestMessage(new JcaPKCS10CertificationRequest(certificationRequest));
        assertEquals("CN=RequestMessageCn,O=PrimeKey,C=SE", requestMessage.getRequestDN());
        EndEntityInformation endEntityInformation = new EndEntityInformation("username", "CN=EndEntityInformationCn,O=PrimeKey,C=SE", 666, null, "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);

        // Create separate key pair that is going to be enforced over one from request message
        KeyPair keyPairEnforcedAlg = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);

        //Create CP and generate certificate
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = x509ca.generateCertificate(cryptoToken, endEntityInformation, requestMessage, keyPairEnforcedAlg.getPublic(), 0, null, null, cp, null, "00000", cceConfig);
        assertNotNull(usercert);

        //RSA_1024 from requestMessage will be overriden with RSA_2048 from separately provided publicKey
        assertEquals("2048", AlgorithmTools.getKeySpecification(usercert.getPublicKey()));
        assertEquals(AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmTools.getKeyAlgorithm(usercert.getPublicKey()));
    }

    /**
     * Testing that CSR algorithm is enforced from end entity information if there is one.
     */
    @Test
    public void testEndEntityInformationCsrAlgorithmEnforced() throws Exception {
        final String algName = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA x509ca = createTestCA(cryptoToken, CADN, algName, null, null);

        // Create a pkcs10 certificate request (the algorithm will be overriden)
        KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        X500Name x509dn = CertTools.stringToBcX500Name("CN=RequestMessageCn,O=PrimeKey,C=SE");
        PKCS10CertificationRequest certificationRequest = CertTools.genPKCS10CertificationRequest(algName, x509dn, keyPair.getPublic(), null, keyPair.getPrivate(), BouncyCastleProvider.PROVIDER_NAME);
        PKCS10RequestMessage requestMessage = new PKCS10RequestMessage(new JcaPKCS10CertificationRequest(certificationRequest));
        assertEquals("CN=RequestMessageCn,O=PrimeKey,C=SE", requestMessage.getRequestDN());

        // Create a pkcs10 certificate request that will be enforced (put inside endEntityInformation.extendedInformation)
        KeyPair keyPairEnforcedAlg = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
        X500Name nameEnforcedAlg = CertTools.stringToBcX500Name("CN=EnforcedAlgCn,O=PrimeKey,C=SE");
        PKCS10CertificationRequest certificationRequestEnforcedAlg = CertTools.genPKCS10CertificationRequest(algName, nameEnforcedAlg, keyPairEnforcedAlg.getPublic(), null, keyPairEnforcedAlg.getPrivate(), BouncyCastleProvider.PROVIDER_NAME);
        PKCS10RequestMessage requestMessageEnforcedAlg = new PKCS10RequestMessage(new JcaPKCS10CertificationRequest(certificationRequestEnforcedAlg));
        assertEquals("CN=EnforcedAlgCn,O=PrimeKey,C=SE", requestMessageEnforcedAlg.getRequestDN());
        EndEntityInformation endEntityInformation = new EndEntityInformation("username", "CN=EndEntityInformationCn,O=PrimeKey,C=SE", 666, null, "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        endEntityInformation.setExtendedInformation(new ExtendedInformation());
        endEntityInformation.getExtendedInformation().setCertificateRequest(certificationRequestEnforcedAlg.getEncoded());

        //Create CP and generate certificate
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = x509ca.generateCertificate(cryptoToken, endEntityInformation, requestMessage, keyPair.getPublic(), 0, null, null, cp, null, "00000", cceConfig);
        assertNotNull(usercert);

        //RSA_1024 from requestMessage will be overriden with RSA_2048 from endEntityInformation.getCertificateRequest
        assertEquals("2048", AlgorithmTools.getKeySpecification(usercert.getPublicKey()));
        assertEquals(AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmTools.getKeyAlgorithm(usercert.getPublicKey()));
    }

    private static ASN1Encodable getValueFromDN(Certificate cert, ASN1ObjectIdentifier oid) {
        final X500Principal principal = ((X509Certificate)cert).getSubjectX500Principal();
        final X500Name xname = X500Name.getInstance(principal.getEncoded());
        final RDN rdn = xname.getRDNs(oid)[0];
        return rdn.getTypesAndValues()[0].getValue();
    }

	private static X509CA createTestCA(CryptoToken cryptoToken, final String cadn) throws Exception {
		return createTestCA(cryptoToken, cadn, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, null, null);
	}

	private static X509CA createTestCA(CryptoToken cryptoToken, final String cadn, final String sigAlg, Date notBefore, Date notAfter) throws Exception {
        cryptoToken.generateKeyPair(getTestKeySpec(sigAlg), CAToken.SOFTPRIVATESIGNKEYALIAS);
        cryptoToken.generateKeyPair(getTestKeySpec(sigAlg), CAToken.SOFTPRIVATEDECKEYALIAS);
        // Create CAToken
        Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
		CAToken caToken = new CAToken(cryptoToken.getId(), caTokenProperties);
		// Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
		caToken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
		caToken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
		caToken.setSignatureAlgorithm(sigAlg);
		caToken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        // No extended services
        X509CAInfo cainfo = new X509CAInfo(cadn, "TEST", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, caToken);
        cainfo.setDescription("JUnit RSA CA");
        X509CA x509ca = new X509CA(cainfo);
        x509ca.setCAToken(caToken);
        // A CA certificate
        final PublicKey publicKey = cryptoToken.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        final PrivateKey privateKey = cryptoToken.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        int keyusage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        X509Certificate cacert = CertTools.genSelfCertForPurpose(cadn, 10L, "1.1.1.1", privateKey, publicKey, sigAlg, true, keyusage, notBefore, notAfter, "BC");
		assertNotNull(cacert);
        List<Certificate> cachain = new ArrayList<Certificate>();
        cachain.add(cacert);
        x509ca.setCertificateChain(cachain);
        // Now our CA should be operational
        return x509ca;
	}

	/** @return a new empty soft auto-activated CryptoToken */
    private CryptoToken getNewCryptoToken() {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo1234");
        CryptoToken cryptoToken;
        try {
            cryptoToken = CryptoTokenFactory.createCryptoToken(
                    SoftCryptoToken.class.getName(), cryptoTokenProperties, null, 17, "CryptoToken's name");
        } catch (NoSuchSlotException e) {
            throw new RuntimeException("Attempted to find a slot for a soft crypto token. This should not happen.");
        }
        return cryptoToken;
    }

    private static KeyPair genTestKeyPair(String algName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        if (algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410)) {
            final String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("gost3410", "B");
            return KeyTools.genKeys(keyspec, AlgorithmConstants.KEYALGORITHM_ECGOST3410);
        } else if(algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145)) {
            final String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("dstu4145", "233");
            return KeyTools.genKeys(keyspec, AlgorithmConstants.KEYALGORITHM_DSTU4145);
        } else if(algName.equals(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA)) {
            return KeyTools.genKeys("brainpoolp224r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        } else {
            return KeyTools.genKeys("512", "RSA");
        }
    }

    /** @return Algorithm name for test key pair */
    private static String getTestKeyPairAlgName(String algName) {
        if (algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410) ||
            algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145) ||
            algName.equals(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA) ||
            algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1)) {
            return algName;
        } else {
            return "SHA256withRSA";
        }
    }

    private static String getTestKeySpec(String algName) {
        if (algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410)) {
            return CesecoreConfiguration.getExtraAlgSubAlgName("gost3410", "B");
        } else if (algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145)) {
            return CesecoreConfiguration.getExtraAlgSubAlgName("dstu4145", "233");
        } else if (algName.equals(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA)) {
            return "brainpoolp224r1";
        } else if (algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1)) {
            return "2048"; // RSA-PSS required at least 2014 bits
        } else {
            return "1024"; // Assume RSA
        }
    }

}
