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
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.TimeZone;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.validation.CertificateValidationDomainService;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.ValidationException;
import org.junit.Test;

import com.keyfactor.util.CeSecoreNameStyle;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.SHA1DigestCalculator;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConfigurationCache;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/** JUnit test for X.509 CA
 *
 */
public class X509CAUnitTest extends X509CAUnitTestBase {

    private static final Logger log = Logger.getLogger(X509CAUnitTest.class);

    // We define this here for compilation, since CT jar is not always available. This is the same as org.certificatetransparency.ctlog.serialization.CTConstants.POISON_EXTENSION_OID

    @Test
    public void testX509CABasicOperationsRSA() throws Exception {
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_SHA512_WITH_RSA);
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1);
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1);
        // AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1 uses small w in With. Test with capital as well
        // because this was used previously so need to be supported for upgraded systems.
        doTestX509CABasicOperations("SHA256WithRSAandMGF1");
    }

    @Test
    public void testX509CABasicOperationsDSA() throws Exception {
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_SHA1_WITH_DSA);
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_SHA256_WITH_DSA);
    }

    @Test
    public void testX509CABasicOperationsGOST() throws Exception {
        assumeTrue(AlgorithmConfigurationCache.INSTANCE.isGost3410Enabled());
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410);
    }

    @Test
    public void testX509CABasicOperationsDSTU() throws Exception {
        assumeTrue(AlgorithmConfigurationCache.INSTANCE.isDstu4145Enabled());
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145);
    }

    @Test
    public void testX509CABasicOperationsECDSA() throws Exception {
        // X509CAUnitTestBase.getTestKeySpec will use prim256v1 for this sigalg
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
    }

    @Test
    public void testX509CABasicOperationsBrainpoolECC() throws Exception {
        // X509CAUnitTestBase.getTestKeySpec will use brainpoolp224r1 for this sigalg
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA);
    }

    @Test
    public void testX509CABasicOperationsEdDSA() throws Exception {
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_ED25519);
        doTestX509CABasicOperations(AlgorithmConstants.SIGALG_ED448);
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
        // ED25519 and ED448 specifies the hash algorithm as part of the signature algo definition
        // See RFC8419, section 3.1
        final String expectedDigest;
        switch (algName) {
        case AlgorithmConstants.SIGALG_ED25519:
            expectedDigest = CMSSignedGenerator.DIGEST_SHA512;
            break;
        case AlgorithmConstants.SIGALG_ED448:
            expectedDigest = NISTObjectIdentifiers.id_shake256_len.getId();
            break;
        default:
            expectedDigest = CMSSignedGenerator.DIGEST_SHA256;
            break;
        }
        assertEquals("CMS/PKCS#7 signature algorithm should use hash algorithm defined by signature algo", expectedDigest, s.getSignerInfos().getSigners().iterator().next().getDigestAlgOID());
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
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com,dnsName=foo.bar.com,directoryName=CN=Tomas\\,O=PrimeKey\\,C=SE", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
        KeyPair keypair = genTestKeyPair(algName);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = x509ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
        assertNotNull(usercert);
        assertEquals("CN=User", CertTools.getSubjectDN(usercert));
        assertEquals(CADN, CertTools.getIssuerDN(usercert));
        assertEquals(getTestKeyPairAlgName(algName).toUpperCase(), CertTools.getCertSignatureAlgorithmNameAsString(usercert).toUpperCase());
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
        Collection<RevokedCertInfo> revcerts = new ArrayList<>();
        Calendar before = Calendar.getInstance();
        before.set(Calendar.MILLISECOND, 0);
        final Date justBefore = before.getTime(); // Round to seconds
        X509CRLHolder crl = x509ca.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 1, null);
        assertNotNull(crl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());
        assertEquals(CADN, CertTools.getIssuerDN(xcrl));
        Set<?> set = xcrl.getRevokedCertificates();
        assertNull(set);
        BigInteger num = CrlExtensions.getCrlNumber(xcrl);
        assertEquals(1, num.intValue());
        BigInteger deltanum = CrlExtensions.getDeltaCRLIndicator(xcrl);
        assertEquals(-1, deltanum.intValue());
        // Check this and next update times
        Calendar after = Calendar.getInstance();
        after.set(Calendar.MILLISECOND, 0);
        final Date justAfter = after.getTime();
        Date nextUpdate = xcrl.getNextUpdate();
        Date thisUpdate = xcrl.getThisUpdate();
        // thisUpdate and nextUpdate is rounded to seconds
        assertTrue("nextUpdate should be after justBefore time: " + nextUpdate + ", " + justBefore, nextUpdate.after(justBefore));
        assertTrue("nextUpdate should be after justAfter time: " + nextUpdate + ", " + justAfter, nextUpdate.after(justAfter));
        assertTrue("thisUpdate should be after or equal to justBefore time: " + thisUpdate.getTime() + ", " + justBefore.getTime(), thisUpdate.equals(justBefore) || thisUpdate.after(justBefore));
        assertTrue("thisUpdate should be before or equal to justAfter time: " + thisUpdate + ", " + justAfter, thisUpdate.equals(justAfter) || thisUpdate.before(justAfter));
        // Revoke some cert
        Date revDate = new Date();
        revcerts.add(new RevokedCertInfo(CertTools.getFingerprintAsString(usercert).getBytes(), CertTools.getSerialNumber(usercert).toByteArray(), revDate.getTime(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, CertTools.getNotAfter(usercert).getTime()));
        crl = x509ca.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 2, null);
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
        ASN1OctetString octs = ASN1OctetString.getInstance(aIn.readObject());
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        ASN1Primitive obj = aIn.readObject();
        CRLReason reason = CRLReason.getInstance(obj);
        assertEquals("CRLReason: certificateHold", reason.toString());

        // Create a delta CRL
        revcerts = new ArrayList<>();
        crl = x509ca.generateDeltaCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 3, 2, null);
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
        crl = x509ca.generateDeltaCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 4, 3, null);
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
        octs = ASN1OctetString.getInstance(aIn.readObject());
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        obj = aIn.readObject();
        reason = CRLReason.getInstance(obj);
        assertEquals("CRLReason: certificateHold", reason.toString());
    }
    
    @Test
    public void testFinalCRLDate() throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA x509ca = createTestCA(cryptoToken, CADN, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, null, null);
        Collection<RevokedCertInfo> revcerts = new ArrayList<>();
        
        // Generate a CRL with default CRL period, should now not create a CRL with max date value
        X509CRLHolder crl = x509ca.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 1, null);
        assertNotNull(crl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());
        // Max date from RFC5280 4.1.2.5, 99991231235959Z
        TimeZone tz = TimeZone.getTimeZone("GMT");
        Calendar cal = Calendar.getInstance(tz);
        cal.set(9999, 11, 31, 23, 59, 59);
        cal.set(Calendar.MILLISECOND, 0); // round to seconds
        assertTrue("nextUpdate of CRL should not be maxvalue from RFC5280, but it was " + xcrl.getNextUpdate(), xcrl.getNextUpdate().before(cal.getTime()));
        
        // Generate a CRL with 9999y as CRL period, should now create a CRL with max date value
        // 365 days per year, 24 hours per day, 3600 seconds per hour, 1000ms per second 
        long l = 9999L*365L*24L*3600L*1000L;
        x509ca.setCRLPeriod(l);
        crl = x509ca.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 1, null);
        assertNotNull(crl);
        xcrl = CertTools.getCRLfromByteArray(crl.getEncoded());
        assertTrue("nextUpdate of CRL should be maxvalue from RFC5280 (" + cal.getTime() + ") but was " + xcrl.getNextUpdate(), xcrl.getNextUpdate().equals(cal.getTime()));
    }

    @Test
    public void testStoreAndLoadRSA() throws Exception {
        doTestStoreAndLoad(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
    }

    @Test
    public void testStoreAndLoadECDSA() throws Exception {
        doTestStoreAndLoad(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
    }

    @Test
    public void testStoreAndLoadGOST() throws Exception {
        assumeTrue(AlgorithmConfigurationCache.INSTANCE.isGost3410Enabled());
        doTestStoreAndLoad(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410);
    }

    @Test
    public void testStoreAndLoadDSTU() throws Exception {
        assumeTrue(AlgorithmConfigurationCache.INSTANCE.isDstu4145Enabled());
        doTestStoreAndLoad(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145);
    }

    private void doTestStoreAndLoad(String algName) throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA ca = createTestCA(cryptoToken, CADN, algName, null, null);

        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
        KeyPair keypair = genTestKeyPair(algName);
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
        byte[] authKeyIdBytes = CertTools.getAuthorityKeyId(usercert);
        assertEquals("Length of method 1 Key Identifier should be langth of SHA1 hash", 20, authKeyIdBytes.length);
        String authKeyId = new String(Hex.encode(authKeyIdBytes));
        String keyhash = CertTools.getFingerprintAsString(cryptoToken.getPublicKey(ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)).getEncoded());
        // Save CA data
        Object o = ca.saveData();

        // Restore CA from data (and other things)
        @SuppressWarnings({ "rawtypes", "unchecked" })
        X509CA ca1 = (X509CA) CAFactory.INSTANCE.getX509CAImpl((HashMap)o, 777, CADN, "test", CAConstants.CA_ACTIVE, new Date(), new Date());

        Certificate usercert1 = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);

        String authKeyId1 = new String(Hex.encode(CertTools.getAuthorityKeyId(usercert1)));
        PublicKey publicKey1 = cryptoToken.getPublicKey(ca1.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        String keyhash1 = CertTools.getFingerprintAsString(publicKey1.getEncoded());
        assertEquals(authKeyId, authKeyId1);
        assertEquals(keyhash, keyhash1);

        CAInfo cainfo = ca.getCAInfo();
        CAData cadata = new CAData(cainfo.getSubjectDN(), cainfo.getName(), cainfo.getStatus(), ca);

        CACommon ca2 = cadata.getCA();
        Certificate usercert2 = ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
        String authKeyId2 = new String(Hex.encode(CertTools.getAuthorityKeyId(usercert2)));
        PublicKey publicKey2 = cryptoToken.getPublicKey(ca2.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        String keyhash2 = CertTools.getFingerprintAsString(publicKey2.getEncoded());
        assertEquals(authKeyId, authKeyId2);
        assertEquals(keyhash, keyhash2);

        // Check CAinfo and CAtokeninfo
        final CAInfo cainfo1 = ca.getCAInfo();
        final CAToken caToken1 = cainfo1.getCAToken();
        assertEquals(algName, caToken1.getSignatureAlgorithm());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, caToken1.getEncryptionAlgorithm());
        assertEquals(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, caToken1.getKeySequenceFormat());

        final CAInfo cainfo2 = ca2.getCAInfo();
        final CAToken caToken2 = cainfo2.getCAToken();
        assertEquals(algName, caToken2.getSignatureAlgorithm());
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
        Collection<ExtendedCAServiceInfo> infos = new ArrayList<>();
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
        X509CA ca1 = (X509CA) CAFactory.INSTANCE.getX509CAImpl((HashMap)o, 777, CADN, "test", CAConstants.CA_ACTIVE, new Date(), new Date());
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
        gns = swapGeneralNames(gns, 0, 5); // Swap rfc822Name and directoryName to test that the order is preserved
        Extension ext = new Extension(Extension.subjectAlternativeName, false, gns.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        ExtensionsGenerator gen = ca.getSubjectAltNameExtensionForCTCert(ext);
        Extensions exts = gen.generate();
        Extension genext = exts.getExtension(Extension.subjectAlternativeName);
        Extension ctext = exts.getExtension(new ASN1ObjectIdentifier(CertTools.id_ct_redacted_domains));
        assertNotNull("A subjectAltName extension should be present", genext);
        assertNull("No CT redated extension should be present", ctext);
        String altName = CertTools.getAltNameStringFromExtension(genext);
        assertEquals("altName is not what it should be", "directoryName=CN=Tomas\\,O=PrimeKey\\,C=SE, iPAddress=192.0.2.123, dNSName=foo.bar.com, dNSName=(PRIVATE).secret.se, dNSName=(PRIVATE).ultrasecret.no, rfc822name=foo@bar.com", altName);
    }

    class TestValidator implements CertificateValidationDomainService {
        @Override
        public void validateCertificate(AuthenticationToken authenticationToken, IssuancePhase phase, CA ca,
                EndEntityInformation endEntityInformation, X509Certificate certificate) throws ValidationException {
        }

        @Override
        public boolean willValidateInPhase(IssuancePhase phase, CA ca) {
            return true;
        }
    }
        
    /** Tests that pre-sign and CT pre-certificate validation works, that the validator is called on a pre-sign certificate (with the hard coded dummy keys)
     * and not signed with the CAs real keys. If validation fails, nothing more should be signed, neither CT pre-cert or a real cert
     * Also tests the order that validations are performed by X509CA 
     * @throws Exception on fatal error
     */
    @Test
    public void testPreCertValidation() throws Exception {
        // Test with CAs using different signature algorithms:
        // RSA, ECDSA, DSA
        // Leaving for future work, or not supported at all: GOST, DSTU
        // The CA code will throw an exception if a key suitable will not be found, so pre certificate validation 
        // is not possible when using GOST or DSTU

        // Create a set of user keypairs for different algs
        KeyPair userKeyPairRSA = genTestKeyPair("SHA256WithRSA");
        KeyPair userKeyPairECDSA = genTestKeyPair("SHA256WithECDSA");
        KeyPair userKeyPairDSA = genTestKeyPair("SHA1WithDSA");
        KeyPair userKeyPairEd25519 = genTestKeyPair(AlgorithmConstants.SIGALG_ED25519);
        KeyPair userKeyPairDilithium3 = genTestKeyPair(AlgorithmConstants.SIGALG_DILITHIUM3);
        KeyPair userKeyPairFalcon512 = genTestKeyPair(AlgorithmConstants.SIGALG_FALCON512);
        // These will return null if GOST or DSTU support is not enabled
        KeyPair userKeyPairGOST = genTestKeyPair("GOST3411withECGOST3410");
        KeyPair userKeyPairDSTU = genTestKeyPair("GOST3411withDSTU4145");

        // Create a CA using SHA256WithRSA as sigAlg
        {
            final CryptoToken cryptoToken = getNewCryptoToken();
            final X509CA x509ca = createTestCA(cryptoToken, CADN);
            runValidatorTests(cryptoToken, x509ca, userKeyPairRSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairECDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairEd25519);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDilithium3);
            runValidatorTests(cryptoToken, x509ca, userKeyPairFalcon512);
            if (userKeyPairGOST != null) {
                runValidatorTests(cryptoToken, x509ca, userKeyPairGOST);
            } else {
                log.info("Not testing GOST");
            }
            if (userKeyPairDSTU != null) {
                runValidatorTests(cryptoToken, x509ca, userKeyPairDSTU);
            } else {
                log.info("Not testing DSTU");
            }
        }

        // Create a CA using SHA256WithECDSA as sigAlg
        {
            final CryptoToken cryptoToken = getNewCryptoToken();
            final X509CA x509ca = createTestCA(cryptoToken, CADN, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, null, null);
            runValidatorTests(cryptoToken, x509ca, userKeyPairRSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairECDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairEd25519);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDilithium3);
            runValidatorTests(cryptoToken, x509ca, userKeyPairFalcon512);
        }

        // Create a CA using SHA1WithDSA as sigAlg
        {
            final CryptoToken cryptoToken = getNewCryptoToken();
            final X509CA x509ca = createTestCA(cryptoToken, CADN, AlgorithmConstants.SIGALG_SHA1_WITH_DSA, null, null);
            runValidatorTests(cryptoToken, x509ca, userKeyPairRSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairECDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairEd25519);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDilithium3);
            runValidatorTests(cryptoToken, x509ca, userKeyPairFalcon512);
        }

        // Create a CA using SHA512WithRSAAndMGF1 (RSA-PSS) as sigAlg
        {
            final CryptoToken cryptoToken = getNewCryptoToken();
            final X509CA x509ca = createTestCA(cryptoToken, CADN, AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1, null, null);
            runValidatorTests(cryptoToken, x509ca, userKeyPairRSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairECDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairEd25519);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDilithium3);
            runValidatorTests(cryptoToken, x509ca, userKeyPairFalcon512);
        }
        // Create a CA using Ed25519 as sigAlg
        {
            final CryptoToken cryptoToken = getNewCryptoToken();
            final X509CA x509ca = createTestCA(cryptoToken, CADN, AlgorithmConstants.SIGALG_ED25519, null, null);
            runValidatorTests(cryptoToken, x509ca, userKeyPairRSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairECDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairEd25519);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDilithium3);
            runValidatorTests(cryptoToken, x509ca, userKeyPairFalcon512);
        }
        // Create a CA using Dilithium3 as sigAlg
        {
            final CryptoToken cryptoToken = getNewCryptoToken();
            final X509CA x509ca = createTestCA(cryptoToken, CADN, AlgorithmConstants.SIGALG_DILITHIUM3, null, null);
            runValidatorTests(cryptoToken, x509ca, userKeyPairRSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairECDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairEd25519);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDilithium3);
            runValidatorTests(cryptoToken, x509ca, userKeyPairFalcon512);
        }
        // Create a CA using Falcon-512 as sigAlg
        {
            final CryptoToken cryptoToken = getNewCryptoToken();
            final X509CA x509ca = createTestCA(cryptoToken, CADN, AlgorithmConstants.SIGALG_FALCON512, null, null);
            runValidatorTests(cryptoToken, x509ca, userKeyPairRSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairECDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDSA);
            runValidatorTests(cryptoToken, x509ca, userKeyPairEd25519);
            runValidatorTests(cryptoToken, x509ca, userKeyPairDilithium3);
            runValidatorTests(cryptoToken, x509ca, userKeyPairFalcon512);
        }
    }
    
    private void runValidatorTests(final CryptoToken cryptoToken, final X509CA x509ca, KeyPair userKeyPair)
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
            OperatorCreationException, CertificateExtensionException, SignatureException, IllegalKeyException, CertificateCreateException {
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        EndEntityInformation user = new EndEntityInformation("testPreCertValidation", "CN=testPreCertValidation", 666, "rfc822Name=user@user.com,dnsName=foo.bar.com,directoryName=CN=Tomas\\,O=PrimeKey\\,C=SE", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
        RequestMessage request = null; // publicKey will be used when this is null
        Extensions extensions = null;
        Date notBefore = null, notAfter = null;

        CertificateGenerationParams certGenParams = new CertificateGenerationParams();
        certGenParams.setAuthenticationToken(new AlwaysAllowLocalAuthenticationToken("testPreSignValidation"));        
        certGenParams.setCertificateValidationDomainService(new TestValidator() {
            @Override
            public void validateCertificate(AuthenticationToken authenticationToken, IssuancePhase phase, CA ca,
                    EndEntityInformation endEntityInformation, X509Certificate certificate) throws ValidationException {
                switch (phase) {
                case DATA_VALIDATION:
                    throw new ValidationException("DATA_VALIDATION");                    
                case CERTIFICATE_VALIDATION:
                    throw new ValidationException("CERTIFICATE_VALIDATION");                    
                case PRE_CERTIFICATE_VALIDATION:
                    throw new ValidationException("PRE_CERTIFICATE_VALIDATION");                    
                case PRESIGN_CERTIFICATE_VALIDATION:
                    throw new ValidationException("PRESIGN_CERTIFICATE_VALIDATION");                    
                default:
                    throw new ValidationException("default");                    
                }
            }
            @Override
            public boolean willValidateInPhase(IssuancePhase phase, CA ca) {
                return false;
            }

        });        

        {
            // Since we have willValidateInPhase == false above, nove pre certificate validation will be done and certificate should be issued
            Certificate cert = x509ca.generateCertificate(cryptoToken, user, request, userKeyPair.getPublic(), 0, notBefore, notAfter, cp, extensions, "00000", certGenParams, cceConfig);
            assertNotNull("A certificate should have been created", cert);
            // Final certificate should have CA key authority key identifier
            byte[] certAuthKeyID = CertTools.getAuthorityKeyId(cert);
            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
            AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(x509ca.getCACertificate().getPublicKey());
            assertEquals("authority key identifier should be from the CA key", Base64.toBase64String(aki.getKeyIdentifier()), Base64.toBase64String(certAuthKeyID));
            // No poison extension in final certificate
            assertNull("There must not be a CT poison extension in the final certificate.", ((X509Certificate)cert).getExtensionValue(CertTools.PRECERT_POISON_EXTENSION_OID));
        }

        // The order of certificate validations executed on a CA should be
        // 1. PRESIGN_CERTIFICATE_VALIDATION, if there is a domain validator (done by X509CA)
        // 2. PRE_CERTIFICATE_VALIDATION, if there is a domain validator and CT is used (done by X509CA)
        // 3. CERTIFICATE_VALIDATION, if there is a domain validator (done by CertificateCreateSessionBean)
        // All require a domain validator, but 2 is skipped if Certificate Transparency is not used
        certGenParams.setCertificateValidationDomainService(new TestValidator() {
            @Override
            public void validateCertificate(AuthenticationToken authenticationToken, IssuancePhase phase, CA ca,
                    EndEntityInformation endEntityInformation, X509Certificate certificate) throws ValidationException {
                switch (phase) {
                case DATA_VALIDATION:
                    throw new ValidationException("DATA_VALIDATION");
                case CERTIFICATE_VALIDATION:
                    throw new ValidationException("CERTIFICATE_VALIDATION");
                case PRE_CERTIFICATE_VALIDATION:
                    throw new ValidationException("PRE_CERTIFICATE_VALIDATION");
                case PRESIGN_CERTIFICATE_VALIDATION:
                    // check the certificate that it is signed with the hard coded key, and has poison extension
                    PublicKey pubK;
                    try {
                        pubK = CAConstants.getPreSignPublicKey(certificate.getSigAlgName(),
                                cryptoToken.getPublicKey(x509ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)));
                    } catch (CryptoTokenOfflineException e) {
                        throw new ValidationException("cannot get CA key");
                    }
                    try {
                        certificate.verify(pubK);
                    } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
                        fail("presign certificate should validate using the presign public key");
                    }
                    // Should not verify with CAs public key
                    try {
                        certificate.verify(ca.getCACertificate().getPublicKey());
                        fail("presign certificate should not verify using the CA public key");
                    } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
                        // NOPMD: expected
                    }
                    assertFalse("presign public key should not be same as certificate public key", ArrayUtils.isEquals(pubK.getEncoded(), certificate.getPublicKey().getEncoded()));
                    // presign certificate should have presign key authority key identifier
                    byte[] certAuthKeyID = CertTools.getAuthorityKeyId(certificate);
                    JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
                    AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(pubK);
                    assertEquals("authority key identifier should be from the hardcoded presign key", Base64.toBase64String(aki.getKeyIdentifier()), Base64.toBase64String(certAuthKeyID));
                    // No poison extension in presign certificate
                    assertNull("There must not be a CT poison extension in the presign certificate.", certificate.getExtensionValue(CertTools.PRECERT_POISON_EXTENSION_OID));
                    throw new ValidationException("PRESIGN_CERTIFICATE_VALIDATION");
                default:
                    throw new ValidationException("default");
                }
            }
        });        
        
        try {
            x509ca.generateCertificate(cryptoToken, user, request, userKeyPair.getPublic(), 0, notBefore, notAfter, cp, extensions, "00000", certGenParams, cceConfig);
            fail("Should throw an exception from the Validator");
        } catch (CertificateCreateException e) {
            if (e.getCause() instanceof ValidationException) {
                ValidationException ve = (ValidationException)e.getCause();
                assertEquals("PRESIGN_CERTIFICATE_VALIDATION should have been run first", "PRESIGN_CERTIFICATE_VALIDATION", ve.getMessage());
            } else {
                fail("Exception cause was expected to be a ValidationException but was " + e.getCause().getClass().getName());                
            }
        }

        // Modify to "pass" PRESIGN_CERTIFICATE_VALIDATION, since we don't have CT configured, it will pass validation 
        certGenParams.setCertificateValidationDomainService(new TestValidator() {
            @Override
            public void validateCertificate(AuthenticationToken authenticationToken, IssuancePhase phase, CA ca,
                    EndEntityInformation endEntityInformation, X509Certificate certificate) throws ValidationException {
                switch (phase) {
                case DATA_VALIDATION:
                    throw new ValidationException("DATA_VALIDATION");                    
                case CERTIFICATE_VALIDATION:
                    throw new ValidationException("CERTIFICATE_VALIDATION");                    
                case PRE_CERTIFICATE_VALIDATION:
                    // check the certificate that it is signed with the CAs key, and has poison extension
                    try {
                        certificate.verify(ca.getCACertificate().getPublicKey());
                    } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
                        fail("CT pre-certificate should validate using the CA public key");
                    }
                    // There must be a poison extension in CT pre-certificate
                    assertNotNull("There must be a CT poison extension in the CT pre-certificate.", certificate.getExtensionValue(CertTools.PRECERT_POISON_EXTENSION_OID));
                    // CT pre-certificate should have CA key authority key identifier
                    byte[] certAuthKeyID = CertTools.getAuthorityKeyId(certificate);
                    JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
                    AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(ca.getCACertificate().getPublicKey());
                    assertEquals("authority key identifier should be from the CA key", Base64.toBase64String(aki.getKeyIdentifier()), Base64.toBase64String(certAuthKeyID));
                    throw new ValidationException("PRE_CERTIFICATE_VALIDATION");                    
                case PRESIGN_CERTIFICATE_VALIDATION:
                    break;                    
                default:
                    throw new ValidationException("default");                    
                }
            }
        });
        {
            Certificate cert = x509ca.generateCertificate(cryptoToken, user, request, userKeyPair.getPublic(), 0, notBefore, notAfter, cp, extensions, "00000", certGenParams, cceConfig);
            assertNotNull("A certificate should have been created", cert);
            // No poison extension in final certificate
            assertNull("Final certificate should not contain CT poison extension", ((X509Certificate)cert).getExtensionValue(CertTools.PRECERT_POISON_EXTENSION_OID));
            try {
                cert.verify(x509ca.getCACertificate().getPublicKey());
            } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
                fail("Final certificate should validate using the CA public key");
            }
        }

        
        // Add CT so that PRE_CERTIFICATE_VALIDATION is run
        // This will only work on Enterprise, since CT is an EE feature
        cp.setUseCertificateTransparencyInCerts(true);
        try {
            Certificate issuedcert = x509ca.generateCertificate(cryptoToken, user, request, userKeyPair.getPublic(), 0, notBefore, notAfter, cp, extensions, "00000", certGenParams, cceConfig);
            if (CertificateTransparencyFactory.getInstance() != null) {
                log.info("EJBCA Enterprise includes CT, PRE_CERTIFICATE_VALIDATION can be done (and fail)");
                fail("Should throw an exception from the Validator");                
            } else {
                log.info("EJBCA Community does not include CT so certificate is issued since no PRE_CERTIFICATE_VALIDATION can be done");
                assertNotNull("Certificate should have been issued", issuedcert);
                // No poison extension in final certificate
                assertNull("There must not be a CT poison extension in the final certificate.", ((X509Certificate)issuedcert).getExtensionValue(CertTools.PRECERT_POISON_EXTENSION_OID));
            }
        } catch (CertificateCreateException e) {
            if (e.getCause() instanceof ValidationException) {
                ValidationException ve = (ValidationException)e.getCause();
                assertEquals("PRE_CERTIFICATE_VALIDATION should have been run first", "PRE_CERTIFICATE_VALIDATION", ve.getMessage());
            } else {
                fail("Exception cause was expected to be a ValidationException but was " + e.getCause().getClass().getName());                
            }
        }
        
        // Make CT pre-certificate, but do not fail validation, so we can issue a real certificate
        // Modify to "pass" PRE_CERTIFICATE_VALIDATION, since we have CT configured, it will pass validation 
        certGenParams.setCertificateValidationDomainService(new TestValidator() {
            @Override
            public void validateCertificate(AuthenticationToken authenticationToken, IssuancePhase phase, CA ca,
                    EndEntityInformation endEntityInformation, X509Certificate certificate) throws ValidationException {
                switch (phase) {
                case DATA_VALIDATION:
                    throw new ValidationException("DATA_VALIDATION");                    
                case CERTIFICATE_VALIDATION:
                    throw new ValidationException("CERTIFICATE_VALIDATION");                    
                case PRE_CERTIFICATE_VALIDATION:
                    // check the certificate that it is signed with the CAs key, and has poison extension
                    try {
                        certificate.verify(ca.getCACertificate().getPublicKey());
                    } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
                        fail("CT pre-certificate should validate using the CA public key");
                    }
                    // There must be a poison extension in CT pre-certificate
                    assertNotNull("There must be a CT poison extension in the CT pre-certificate.", certificate.getExtensionValue(CertTools.PRECERT_POISON_EXTENSION_OID));
                    // CT pre-certificate should have CA key authority key identifier
                    byte[] certAuthKeyID = CertTools.getAuthorityKeyId(certificate);
                    JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
                    AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(ca.getCACertificate().getPublicKey());
                    assertEquals("authority key identifier should be from the CA key", Base64.toBase64String(aki.getKeyIdentifier()), Base64.toBase64String(certAuthKeyID));
                    break;
                case PRESIGN_CERTIFICATE_VALIDATION:
                    break;                    
                default:
                    throw new ValidationException("default");                    
                }
            }
        });
        {
            Certificate cert = x509ca.generateCertificate(cryptoToken, user, request, userKeyPair.getPublic(), 0, notBefore, notAfter, cp, extensions, "00000", certGenParams, cceConfig);
            assertNotNull("A certificate should have been created", cert);
            // No poison extension in final certificate
            assertNull("Final certificate should not contain CT poison extension", ((X509Certificate)cert).getExtensionValue(CertTools.PRECERT_POISON_EXTENSION_OID));
            try {
                cert.verify(x509ca.getCACertificate().getPublicKey());
            } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
                fail("Final certificate should validate using the CA public key");
            }
        }
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
        assumeTrue(AlgorithmConfigurationCache.INSTANCE.isGost3410Enabled());
        doTestWrongCAKey(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410);
    }

    @Test
    public void testWrongCAKeyDSTU() throws Exception {
        assumeTrue(AlgorithmConfigurationCache.INSTANCE.isDstu4145Enabled());
        doTestWrongCAKey(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145);
    }

    public void doTestWrongCAKey(String algName) throws Exception {
        final CryptoToken cryptoToken = getNewCryptoToken();
        X509CA x509ca = createTestCA(cryptoToken, CADN, algName, null, null);

        // Generate a client certificate and check that it was generated correctly
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
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
        } catch (CertificateCreateException e) {
            assertEquals("Error message should be what we expect", 
                    "Public key in the CA certificate does not match the configured certSignKey, is the CA in renewal process? : certificate does not verify with supplied key", 
                    e.getMessage());
        } 
        try {
            Collection<RevokedCertInfo> revcerts = new ArrayList<>();
            x509ca.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 1, null);
            fail("should not work to issue this CRL");
        } catch (SignatureException e) {
            Certificate cacert = x509ca.getCACertificate();
            PublicKey verifyKey = cacert.getPublicKey();
            String expectedMsg = "Cannot verify the signature of the CRL for issuer " + "'" + CADN
            + "' using the public key with SHA-1 fingerprint " + CertTools.createPublicKeyFingerprint(verifyKey, "SHA-1")
            + ". The CRL signature was created with a private key stored in the token " + cryptoToken.getTokenName()
            + ". The most likely reason for this error is that the private key stored on the token does not correspond to the public key found in the issuer certificate.";
            assertEquals("Error message should be what we expect", expectedMsg, e.getMessage());
        }

        // New CA certificate to make it work again
        PublicKey publicKey = cryptoToken.getPublicKey(x509ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        PrivateKey privateKey = cryptoToken.getPrivateKey(x509ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        X509Certificate cacert = CertTools.genSelfCert(CADN, 10L, "1.1.1.1", privateKey, publicKey, "SHA256WithRSA", true);
        assertNotNull(cacert);
        List<Certificate> cachain = new ArrayList<>();
        cachain.add(cacert);
        x509ca.setCertificateChain(cachain);
        usercert = x509ca.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
        assertNotNull(usercert);
        Collection<RevokedCertInfo> revcerts = new ArrayList<>();
        X509CRLHolder crl = x509ca.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 1, null);
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
                new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
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
                new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
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
                new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
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

    /** Test implementation of Authority Information Access Extension for OCSP and CRL according to RFC 4325 */
    @Test
    public void testAuthorityInformationAccessCertificateExtension() throws Exception {
        // test data for CA - level
        final List<String> caIssuerUris = new ArrayList<>();
        caIssuerUris.add( "http://ca-defined.ca.issuer.uri1.sw");
        caIssuerUris.add( "http://ca-defined.ca.issuer.uri2.sw");
        final List<String> ocspUrls = new ArrayList<>();
        ocspUrls.add("http://ca-defined.ocsp.service.locator.url.sw");
        // test data for certificate profile - level
        final List<String> cpCaIssuerUris = new ArrayList<>();
        cpCaIssuerUris.add( "http://certificate-profile.ca.issuer.uri1.sw");
        cpCaIssuerUris.add( "http://certificate-profile.ca.issuer.uri2.sw");
        final List<String> cpOcspUrls = new ArrayList<>();
        cpOcspUrls.add("http://certificate-profile.ocsp.service.locator.url.sw");
        // set up test CA, end entity and certificate profile
        final CryptoToken cryptoToken = getNewCryptoToken();
        final KeyPair keypair = KeyTools.genKeys("1024", "RSA");
        final X509CA ca = createTestCA(cryptoToken, "CN=foo");
        final EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
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
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
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
        Collection<RevokedCertInfo> revcerts = new ArrayList<>();
        X509CRLHolder testCrl = testCa.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 0, null);
        assertNotNull(testCrl);
        X509CRL xcrl = CertTools.getCRLfromByteArray(testCrl.getEncoded());
        Collection<String> result = CertTools.getAuthorityInformationAccess(xcrl);
        assertEquals("A list was returned without any values present.", 0, result.size());
        // Issue a certificate with two different basic certificate extensions
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com,dnsName=foo.bar.com,directoryName=CN=Tomas\\,O=PrimeKey\\,C=SE", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
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
        List<Integer> list = new ArrayList<>();
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
        ASN1OctetString oct = ASN1OctetString.getInstance(is.readObject());
        is.close();
        ASN1InputStream is2 = new ASN1InputStream(oct.getOctets());
        DERIA5String str = (DERIA5String)is2.readObject();
        is2.close();
        assertEquals("Hello World", str.getString());

        byte[] ext2 = cert.getExtensionValue("1.2.3.4");
        is = new ASN1InputStream(ext2);
        oct = ASN1OctetString.getInstance(is.readObject());
        is.close();
        is2 = new ASN1InputStream(oct.getOctets());
        ASN1Sequence seq = ASN1Sequence.getInstance(is2.readObject());
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
        oct = ASN1OctetString.getInstance(is.readObject());
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
        final EndEntityInformation subject = new EndEntityInformation("cert policy extension test", subjectDN, testCa.getCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
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
        ASN1IA5String str = ASN1IA5String.getInstance(pqi.getQualifier());
        assertEquals("https://ejbca.org/2", str.getString());

        // The second Policy object has a CPS URI
        qualifier = pi.get(1).getPolicyQualifiers().getObjectAt(0);
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_cps = 1.3.6.1.5.5.7.2.1
        assertEquals(PolicyQualifierId.id_qt_cps.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_cps, we know this is a DERIA5String
        str = ASN1IA5String.getInstance(pqi.getQualifier());
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
        str = ASN1IA5String.getInstance(pqi.getQualifier());
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
        final EndEntityInformation subject = new EndEntityInformation("testPrintableString", subjectDN, testCa.getCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
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
        // From BC 1.65 we set our CeSecoreNameStyle as default style for X500Name, which makes EV DN components available
        // before 1.65 it would be
        //assertEquals("Wrong DN name of Test CA", "1.3.6.1.4.1.311.60.2.1.3=DE,1.3.6.1.4.1.311.60.2.1.2=Stockholm,1.3.6.1.4.1.311.60.2.1.1=Solna,CN=foo CA,O=Bar,C=SE", name.toString());       
        assertEquals("Wrong DN name of Test CA", "JurisdictionCountry=DE,JurisdictionState=Stockholm,JurisdictionLocality=Solna,CN=foo CA,O=Bar,C=SE", name.toString());

        // Test generation by calling generateCertificate directly
        final String subjectDN = "JurisdictionCountry=NL,JurisdictionState=State,JurisdictionLocality=Åmål,BusinessCategory=Private Organization,CN=evssltest6.test.lan,SN=1234567890,OU=XY,O=MyOrg B.V.,L=Åmål,ST=Norrland,C=SE";
        final EndEntityInformation subject = new EndEntityInformation("testPrintableString", subjectDN, testCa.getCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
        final CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cert = testCa.generateCertificate(cryptoToken, subject, cert.getPublicKey(), KeyUsage.digitalSignature | KeyUsage.keyEncipherment, null, "30d", certProfile, null, cceConfig);
        princ = ((X509Certificate) cert).getSubjectX500Principal();
        name = X500Name.getInstance(princ.getEncoded());
        // This is standard order where EV fields are before CN and in other respects ldap order
        // From BC 1.65 we set our CeSecoreNameStyle as default style for X500Name, which makes EV DN components available, the same with SERIALNUMBER is called SN
        String desiredDN = "JurisdictionCountry=NL,JurisdictionState=State,JurisdictionLocality=Åmål,BusinessCategory=Private Organization,CN=evssltest6.test.lan,SN=1234567890,OU=XY,O=MyOrg B.V.,L=Åmål,ST=Norrland,C=SE";
        assertEquals("Wrong DN order of issued certificate", desiredDN, name.toString());
        // Now set a DN order where the EV fields (and serialnumber and businesscategory) comes before C and in other aspects are x500 order
        final ArrayList<String> order = new ArrayList<>(Arrays.asList("jurisdictioncountry", "jurisdictionstate", "jurisdictionlocality","businesscategory","serialnumber","c","dc","st","l","o","ou","t","surname","initials","givenname","gn","sn","name","cn","uid","dn","email","e","emailaddress","unstructuredname","unstructuredaddress","postalcode","postaladdress","telephonenumber","pseudonym","street"));
        certProfile.setCustomDnOrder(order);
        certProfile.setUseCustomDnOrder(true);
        cert = testCa.generateCertificate(cryptoToken, subject, cert.getPublicKey(), KeyUsage.digitalSignature | KeyUsage.keyEncipherment, null, "30d", certProfile, null, cceConfig);
        princ = ((X509Certificate) cert).getSubjectX500Principal();
        name = X500Name.getInstance(princ.getEncoded());
        // From BC 1.65 we set our CeSecoreNameStyle as default style for X500Name, which makes EV DN components available, the same with SERIALNUMBER is called SN
        desiredDN = "JurisdictionCountry=NL,JurisdictionState=State,JurisdictionLocality=Åmål,BusinessCategory=Private Organization,SN=1234567890,C=SE,ST=Norrland,L=Åmål,O=MyOrg B.V.,OU=XY,CN=evssltest6.test.lan";
        assertEquals("Wrong DN order of issued certificate", desiredDN, name.toString());
    }
    

    /**
     * Regression test to make sure that a certificate can't be created with notBefore and notAfter both in the past. 
     */
    @Test
    public void testNotBeforeAndNotAfterInPast() throws InvalidAlgorithmParameterException, CertificateParsingException, CryptoTokenOfflineException,
            InvalidAlgorithmException, OperatorCreationException, CAOfflineException, IllegalValidityException, IllegalNameException,
            CertificateCreateException, SignatureException, IllegalKeyException, CertificateExtensionException {
        final String caDn = "CN=testNotBeforeAndNotAfterInPastCA";
        final String username = "testNotBeforeAndNotAfterInPast";
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setAllowValidityOverride(true);
        EndEntityInformation endEntityInformation = new EndEntityInformation();
        endEntityInformation.setType(EndEntityTypes.ENDUSER.toEndEntityType());
        endEntityInformation.setUsername(username);
        endEntityInformation.setDN("CN=" + username);
        endEntityInformation.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        endEntityInformation.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityInformation.setPassword("foo123");
        //Two days ago
        Date notBefore = new Date(System.currentTimeMillis() - 1000 * 3600 * 24 * 2);
        //One day ago
        Date notAfter = new Date(System.currentTimeMillis() - 1000 * 3600 * 24 * 1);
        KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA testCa = createTestCA(cryptoToken, caDn);

        try {
            testCa.generateCertificate(cryptoToken, endEntityInformation, null, keyPair.getPublic(), 0, notBefore, notAfter, certificateProfile, null, "00000", cceConfig);
            fail("Certificate creation using both notBefore and notAfter in the past should have failed.");
        } catch (IllegalValidityException e) {
            //NOMPD: All is well
        }
    }
    
    /**
     * Regression test to make sure that back dated revocation is still allowed
     */
    @Test
    public void testAllowBackdatedRevocation() throws InvalidAlgorithmParameterException, CertificateParsingException, CryptoTokenOfflineException,
            InvalidAlgorithmException, OperatorCreationException, CAOfflineException, IllegalValidityException, IllegalNameException,
            CertificateCreateException, SignatureException, IllegalKeyException, CertificateExtensionException {
        final String caDn = "CN=testNotBeforeAndNotAfterInPastCA";
        final String username = "testNotBeforeAndNotAfterInPast";
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setAllowValidityOverride(true);
        EndEntityInformation endEntityInformation = new EndEntityInformation();
        endEntityInformation.setType(EndEntityTypes.ENDUSER.toEndEntityType());
        endEntityInformation.setUsername(username);
        endEntityInformation.setDN("CN=" + username);
        endEntityInformation.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        endEntityInformation.setStatus(EndEntityConstants.STATUS_REVOKED);
        endEntityInformation.setPassword("foo123");
        //Two days ago
        Date notBefore = new Date(System.currentTimeMillis() - 1000 * 3600 * 24 * 2);
        //One day ago
        Date notAfter = new Date(System.currentTimeMillis() - 1000 * 3600 * 24 * 1);
        KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA testCa = createTestCA(cryptoToken, caDn);

        try {
            testCa.generateCertificate(cryptoToken, endEntityInformation, null, keyPair.getPublic(), 0, notBefore, notAfter, certificateProfile, null, "00000", cceConfig);
        } catch (IllegalValidityException e) {
            fail("Back dated revoked certificate should have been created.");
        }
    }
    
    /**
     * Regression test to make sure that back dated link certificates are still allowed
     */
    @Test
    public void testAllowBackdatedLinkCertificates() throws Throwable {
        final String caDn = "CN=testNotBeforeAndNotAfterInPastCA";
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setAllowValidityOverride(true);
        //Two days ago
        Date notBefore = new Date(System.currentTimeMillis() - 1000 * 3600 * 24 * 2);
        //One day ago
        Date notAfter = new Date(System.currentTimeMillis() - 1000 * 3600 * 24 * 1);
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA testCa = createTestCA(cryptoToken, caDn);
        Method generateCertificate = X509CAImpl.class.getDeclaredMethod("generateCertificate", EndEntityInformation.class, RequestMessage.class,
                PublicKey.class, int.class, Date.class, Date.class, CertificateProfile.class, Extensions.class, PublicKey.class, PrivateKey.class,
                String.class, CertificateGenerationParams.class, AvailableCustomCertificateExtensionsConfiguration.class, boolean.class,
                boolean.class);
        generateCertificate.setAccessible(true);
        CAToken caToken = testCa.getCAToken();       
        final PublicKey previousCaPublicKey = cryptoToken.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
        final PrivateKey previousCaPrivateKey = cryptoToken.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
        final EndEntityInformation cadata = new EndEntityInformation("nobody", testCa.getSubjectDN(), testCa.getSubjectDN().hashCode(), testCa.getSubjectAltName(), null,
                0, new EndEntityType(EndEntityTypes.INVALID), 0, testCa.getCertificateProfileId(), null, null, 0, null);
        try {
            generateCertificate.invoke(testCa, cadata, null, cryptoToken.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT)), 0, notBefore, notAfter, certificateProfile,
                    null, previousCaPublicKey, previousCaPrivateKey, BouncyCastleProvider.PROVIDER_NAME, null, cceConfig, true, false);
        } catch (InvocationTargetException e) {
            if(e.getCause() instanceof IllegalValidityException) {
            fail("Back dated revoked certificate should have been created.");
            } else {
                throw e.getCause();
            }
       }      
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
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, null, "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = x509ca.generateCertificate(cryptoToken, user, p10msg, keyPair.getPublic(), 0, null, null, cp, null, "00000", cceConfig);
        assertNotNull(usercert);
        assertEquals("CN=User", CertTools.getSubjectDN(usercert));
        assertEquals(CADN, CertTools.getIssuerDN(usercert));
        assertEquals(getTestKeyPairAlgName(algName).toUpperCase(), CertTools.getCertSignatureAlgorithmNameAsString(usercert).toUpperCase());
        assertEquals(new String(CertTools.getSubjectKeyId(cacert)), new String(CertTools.getAuthorityKeyId(usercert)));
        // Allow DN override
        cp.setAllowDNOverride(true);
        usercert = x509ca.generateCertificate(cryptoToken, user, p10msg, keyPair.getPublic(), 0, null, null, cp, null, "00000", cceConfig);
        assertNotNull(usercert);
        assertEquals("CN=Override,O=PrimeKey,C=SE", CertTools.getSubjectDN(usercert));
        assertEquals(CADN, CertTools.getIssuerDN(usercert));
        assertEquals(getTestKeyPairAlgName(algName).toUpperCase(), CertTools.getCertSignatureAlgorithmNameAsString(usercert).toUpperCase());
        assertEquals(new String(CertTools.getSubjectKeyId(cacert)), new String(CertTools.getAuthorityKeyId(usercert)));
    }

    /**
     * Testing that the certificate's serial number is generated with the correct length, according to "serial number octet size" that is configured to CA.
     * "serial number octet size" is left to be default 20 bytes here
     */ 
    @Test
    public void testCaSerialNumberWithDefaultOctetSize20() throws Exception {
        final String algName = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA x509ca = createTestCA(cryptoToken, CADN, algName, null, null);
        
        KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, null, "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = x509ca.generateCertificate(cryptoToken, user, null, keyPair.getPublic(), 0, null, null, cp, null, "00000", cceConfig);
        assertNotNull(usercert);
        BigInteger serialNumber = CertTools.getSerialNumber(usercert);
        
        BigInteger lowestBound = new BigInteger("0080000000000000000000000000000000000000", 16);
        BigInteger highestBound = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        assertTrue(serialNumber.compareTo(lowestBound) >= 0 && serialNumber.compareTo(highestBound) <= 0);
    }
    
    /**
     * Testing that the certificate's serial number is generated with the correct length, according to "serial number octet size" that is configured to CA.
     * "serial number octet size" is configured to be 4 bytes here
     */
    @Test
    public void testCaSerialNumberWithOctetSize4() throws Exception {
        final String algName = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA x509ca = createTestCA(cryptoToken, CADN, algName, null, null);
        
        // set the octet size to 4 (overwriting the default value 20)
        x509ca.setCaSerialNumberOctetSize(4);
        
        KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, null, "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        Certificate usercert = x509ca.generateCertificate(cryptoToken, user, null, keyPair.getPublic(), 0, null, null, cp, null, "00000", cceConfig);
        assertNotNull(usercert);
        BigInteger serialNumber = CertTools.getSerialNumber(usercert);
        
        BigInteger lowestBound = new BigInteger("00800000", 16);
        BigInteger highestBound = new BigInteger("7FFFFFFF", 16);
        assertTrue(serialNumber.compareTo(lowestBound) >= 0 && serialNumber.compareTo(highestBound) <= 0);
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
        EndEntityInformation endEntityInformation = new EndEntityInformation("username", "CN=EndEntityInformationCn,O=PrimeKey,C=SE", 666, null, "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);

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
     * Testing generating certificate with public key from providedRequestMessage (providedPublicKey and endEntityInformation.extendedInformation.certificateRequest must be null).
     * Tests the three different encodings of EC public keys:
     * - With named curve and non-compressed point (standard RFC5280/3779)
     * - With named curve and compressed point (MAY in RFC3779, compliant with NIST EC key validation)
     * - With full curve parameters (ICAO9303)
     */
    @Test
    public void testGeneratingCertificateWithECPublicKeyWithDifferentEncodingsFromProvidedRequestMessage() throws Exception {
        final String algName = AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA x509ca = createTestCA(cryptoToken, CADN, algName, null, null);

        // Generate a key pair and encode the public key in three different ways
        KeyPair keyPair = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
        // 1. With named curve and non-compressed point
        BCECPublicKey bcEcPub = (BCECPublicKey)(keyPair.getPublic());
        byte[] namedNonCompressed = bcEcPub.getEncoded();
        // 2. With named curve and compressed point
        bcEcPub.setPointFormat("COMPRESSED");
        byte[] namedCompressed = bcEcPub.getEncoded();
        // 3. With full curve parameters
        byte[] fullParams = ECKeyUtil.publicToExplicitParameters(bcEcPub, BouncyCastleProvider.PROVIDER_NAME).getEncoded();

        // Generate three different PKCS#10 CSRs with the same public key encoded in three different ways
        // 1. With named curve and non-compressed point
        X500Name x509dn = CertTools.stringToBcX500Name("CN=RequestMessageCn");
        PKCS10CertificationRequest certificationRequest = genPKCS10CertificationRequest(algName, x509dn, namedNonCompressed, keyPair.getPrivate());
        PKCS10RequestMessage csrNamedNonCompressed = new PKCS10RequestMessage(new JcaPKCS10CertificationRequest(certificationRequest));
        assertTrue("Our own generated CSR with uncompressed key does not verify POP, it definitely should", csrNamedNonCompressed.verify(keyPair.getPublic()));
        assertTrue("Our own generated CSR with uncompressed key (JCA format) does not verify POP, it definitely should", csrNamedNonCompressed.verify(new JcaPKCS10CertificationRequest(csrNamedNonCompressed.getCertificationRequest()).getPublicKey()));
        assertEquals("CN=RequestMessageCn", csrNamedNonCompressed.getRequestDN());
        // 2. With named curve and compressed point
        certificationRequest = genPKCS10CertificationRequest(algName, x509dn, namedCompressed, keyPair.getPrivate());
        PKCS10RequestMessage csrNamedCompressed = new PKCS10RequestMessage(new JcaPKCS10CertificationRequest(certificationRequest));
        assertTrue("Our own generated CSR with compressed key does not verify POP, it definitely should", csrNamedCompressed.verify(keyPair.getPublic()));
        assertTrue("Our own generated CSR with compressed key (JCA format) does not verify POP, it definitely should", csrNamedCompressed.verify(new JcaPKCS10CertificationRequest(csrNamedCompressed.getCertificationRequest()).getPublicKey()));
        assertEquals("CN=RequestMessageCn", csrNamedCompressed.getRequestDN());
        // 3. With full curve parameters
        certificationRequest = genPKCS10CertificationRequest(algName, x509dn, fullParams, keyPair.getPrivate());
        PKCS10RequestMessage csrFullParams = new PKCS10RequestMessage(new JcaPKCS10CertificationRequest(certificationRequest));
        assertTrue("Our own generated CSR with full parameters does not verify POP, it definitely should", csrFullParams.verify(keyPair.getPublic()));
        assertTrue("Our own generated CSR with full parameters (JCA format) does not verify POP, it definitely should", csrFullParams.verify(new JcaPKCS10CertificationRequest(csrFullParams.getCertificationRequest()).getPublicKey()));
        assertEquals("CN=RequestMessageCn", csrFullParams.getRequestDN());
        
        // Verify that the CSRs seem to be generated with the intended encoding
        // the magic numbers for first bytes are 0x00 (infinity) 0x02 (compressed) 0x03 (compressed, negate Y), 0x04 (uncompressed). 
        // You'll never see 0.
        byte[] encoding = csrNamedNonCompressed.getCertificationRequest().getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
        assertEquals("The magic number is not for an uncomressed key", 4, encoding[0]);
        X962Parameters params = X962Parameters.getInstance(csrNamedNonCompressed.getCertificationRequest().getSubjectPublicKeyInfo().getAlgorithm().getParameters());
        assertTrue("The uncompressed key does not use a named curve parameter", params.isNamedCurve());
        encoding = csrNamedCompressed.getCertificationRequest().getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
        assertTrue("First byte is not 2 or 3 as it should for a compressed key: " + encoding[0], (encoding[0] == 2 || encoding[0] == 3));
        params = X962Parameters.getInstance(csrNamedCompressed.getCertificationRequest().getSubjectPublicKeyInfo().getAlgorithm().getParameters());
        assertTrue("The compressed key does not use a named curve parameter", params.isNamedCurve());
        encoding = csrFullParams.getCertificationRequest().getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
        assertEquals("The magic number is not for an uncomressed key (full parameters test)", 4, encoding[0]); // full parameters is also non-compressed
        params = X962Parameters.getInstance(csrFullParams.getCertificationRequest().getSubjectPublicKeyInfo().getAlgorithm().getParameters());
        assertFalse("The full parameters key uses a named curve parameter", params.isNamedCurve());

        // CP and EE Info
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
        cp.setUseCertificatePolicies(true);
        EndEntityInformation endEntityInformation = new EndEntityInformation("username", "CN=EndEntityInformationCn,O=PrimeKey,C=SE", 666, null, "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);

        // Generate three certificates, one from each CSR
        // 1. With named curve and non-compressed point
        Certificate certNamedNonCompressed = x509ca.generateCertificate(cryptoToken, endEntityInformation, csrNamedNonCompressed, /*providedPublicKey=*/null, 0, null, null, cp, null, "00000", cceConfig);
        assertNotNull("Uncompressed key certificate could not be created", certNamedNonCompressed);
        PublicKey certPub = certNamedNonCompressed.getPublicKey();
        assertEquals("Key algorithm is not as expected", "prime256v1", AlgorithmTools.getKeySpecification(certPub)); // prime256v1 is same as secp256r1
        assertEquals(AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmTools.getKeyAlgorithm(certPub));
        assertTrue("Public key is not an in stance of BCECPUblicKey: " + certPub.getClass().getName(), certPub instanceof BCECPublicKey);
        BCECPublicKey ecPub = (BCECPublicKey)certPub;
        assertTrue("Public key is not encoded as a named curve", ecPub.getParams() instanceof ECNamedCurveSpec);
        X509CertificateHolder holder = new X509CertificateHolder(certNamedNonCompressed.getEncoded());
        byte[] pkBytes = holder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
        // the magic numbers for first bytes are 0x00 (infinity) 0x02 (compressed) 0x03 (compressed, negate Y), 0x04 (uncompressed). 
        // You'll never see 0.
        assertEquals("The magic number is not for an uncomressed key", 4, pkBytes[0]);
        params = X962Parameters.getInstance(holder.getSubjectPublicKeyInfo().getAlgorithm().getParameters());
        assertTrue("The uncompressed key does not use a named curve parameter", params.isNamedCurve());

        // 2. With named curve and compressed point
        Certificate certNamedCompressed = x509ca.generateCertificate(cryptoToken, endEntityInformation, csrNamedCompressed, /*providedPublicKey=*/null, 0, null, null, cp, null, "00000", cceConfig);
        assertNotNull("Compressed key certificate could not be created", certNamedCompressed);        
        certPub = certNamedCompressed.getPublicKey();
        assertEquals("Key algorithm is not as expected", "prime256v1", AlgorithmTools.getKeySpecification(certPub));
        assertEquals(AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmTools.getKeyAlgorithm(certPub));
        assertTrue("Public key is not an in stance of BCECPUblicKey: " + certPub.getClass().getName(), certPub instanceof BCECPublicKey);
        ecPub = (BCECPublicKey)certPub;
        assertTrue("Public key is not encoded as a named curve", ecPub.getParams() instanceof ECNamedCurveSpec);
        holder = new X509CertificateHolder(certNamedCompressed.getEncoded());
        pkBytes = holder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
        assertTrue("First byte is not 2 or 3 as it should be for a compressed key: " + pkBytes[0], (pkBytes[0] == 2 || pkBytes[0] == 3));
        params = X962Parameters.getInstance(holder.getSubjectPublicKeyInfo().getAlgorithm().getParameters());
        assertTrue("The compressed key does not use a named curve parameter", params.isNamedCurve());

        // 3. With full curve parameters
        Certificate certFullParams = x509ca.generateCertificate(cryptoToken, endEntityInformation, csrFullParams, /*providedPublicKey=*/null, 0, null, null, cp, null, "00000", cceConfig);
        assertNotNull("Full parameters key certificate could not be created", certFullParams);        
        certPub = certFullParams.getPublicKey();
        assertEquals("Key algorithm is not as expected", "P-256", AlgorithmTools.getKeySpecification(certPub)); // For full parameters P-256 is returned instead of prime256v1, but it's the same
        assertEquals(AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmTools.getKeyAlgorithm(certPub));
        assertTrue("Public key is not an in stance of BCECPUblicKey: " + certPub.getClass().getName(), certPub instanceof BCECPublicKey);
        ecPub = (BCECPublicKey)certPub;
        assertFalse("Public key is encoded as a named curve", ecPub.getParams() instanceof ECNamedCurveSpec);
        holder = new X509CertificateHolder(certFullParams.getEncoded());
        pkBytes = holder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
        assertEquals("The magic number is not for an uncomressed key", 4, pkBytes[0]);
        params = X962Parameters.getInstance(holder.getSubjectPublicKeyInfo().getAlgorithm().getParameters());
        assertFalse("The full parameters key does not use a named curve parameter", params.isNamedCurve());
    }

    // See CertTools.genPKCS10CertificationRequest, modified to take differently encoded public keys
    private static PKCS10CertificationRequest genPKCS10CertificationRequest(String signatureAlgorithm, X500Name subject, byte[] encodedPublickey,
            PrivateKey privateKey) throws OperatorCreationException {
        ContentSigner signer;
        CertificationRequestInfo reqInfo;
        try {
            SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(encodedPublickey);
            reqInfo = new CertificationRequestInfo(subject, pkinfo, null);
            signer = new BufferingContentSigner(new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey), 20480);
            signer.getOutputStream().write(reqInfo.getEncoded(ASN1Encoding.DER));
            signer.getOutputStream().flush();
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException was caught.", e);
        }
        byte[] sig = signer.getSignature();
        DERBitString sigBits = new DERBitString(sig);
        CertificationRequest req = new CertificationRequest(reqInfo, signer.getAlgorithmIdentifier(), sigBits);
        return new PKCS10CertificationRequest(req);
    }

    /**
     * Testing that we fill in AlgorithmIdentifier parameters for RSA keys where this is missing. According to RFC 3279 we need to add DERNull
     * instead of just leaving out the AlgorithmID parameters. The params are not used but must be ASN.1 encoded correctly in order to comply with
     * RFC5280. Some client software has been known to generate CSRs where the parameters are missing (which is not invalid ASN.1 encoding, but violates RFC5280/RFC3279).
     * 
     * SubjectPublicKeyInfo ::= SEQUENCE {
     *   algorithm AlgorithmIdentifier,
     *   subjectPublicKey BIT STRING }
     *   
     * AlgorithmIdentifier ::= SEQUENCE {
     *   algorithm OBJECT IDENTIFIER,
     *   parameters ANY DEFINED BY algorithm OPTIONAL }
     */
    @Test
    public void testGeneratingCertificateWithPublicKeyWithoutAlgIDParams() throws Exception {
        final String algName = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        final CryptoToken cryptoToken = getNewCryptoToken();
        final X509CA x509ca = createTestCA(cryptoToken, CADN, algName, null, null);
        
        KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, null, "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        // before starting to crap it up, double check that what we have is a compliant publicKey
        {
            SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
            assertEquals("Public key should be RSA, this is what we generated", PKCSObjectIdentifiers.rsaEncryption.getId(), pkinfo.getAlgorithm().getAlgorithm().getId());
            ASN1Encodable params = pkinfo.getAlgorithm().getParameters();
            assertNotNull("AlgorithmID parameters should not be null in a properly generated RSA Public Key", params);
            assertEquals("Params should be DERNull", DERNull.INSTANCE, params);
        }
        // meddle with the public key to remove algorithmID parameters
        SubjectPublicKeyInfo keyinfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        AlgorithmIdentifier id = new AlgorithmIdentifier(keyinfo.getAlgorithm().getAlgorithm(), null);
        SubjectPublicKeyInfo keyinfoFinal = new SubjectPublicKeyInfo(id, keyinfo.parsePublicKey());        
        X509EncodedKeySpec xspec = new X509EncodedKeySpec(keyinfoFinal.getEncoded());
        KeyFactory kFact = KeyFactory.getInstance("RSA", "BC");
        PublicKey pubKeyFinal = kFact.generatePublic(xspec);
        // Ok, this was cumbersome, double check that we got what we wanted, a non-compliant publicKey
        {
            SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(pubKeyFinal.getEncoded());
            assertEquals("Public key should be RSA, this is what we generated", PKCSObjectIdentifiers.rsaEncryption.getId(), pkinfo.getAlgorithm().getAlgorithm().getId());
            ASN1Encodable params = pkinfo.getAlgorithm().getParameters();
            assertNull("AlgorithmID parameters should be null that is what we tried to make sure", params);
        }
        Certificate usercert = x509ca.generateCertificate(cryptoToken, user, null, pubKeyFinal, 0, null, null, cp, null, "00000", cceConfig);
        assertNotNull(usercert);
        SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(usercert.getPublicKey().getEncoded());
        assertEquals("Public key should be RSA, this is what we sent in to the request", PKCSObjectIdentifiers.rsaEncryption.getId(), pkinfo.getAlgorithm().getAlgorithm().getId());
        ASN1Encodable params = pkinfo.getAlgorithm().getParameters();
        assertNotNull("AlgorithmID parameters must not be null for an RSA public key, see RFC3279", params);
        assertEquals("Params should be DERNull", DERNull.INSTANCE, params);
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
        EndEntityInformation endEntityInformation = new EndEntityInformation("username", "CN=EndEntityInformationCn,O=PrimeKey,C=SE", 666, null, "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);

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
        EndEntityInformation endEntityInformation = new EndEntityInformation("username", "CN=EndEntityInformationCn,O=PrimeKey,C=SE", 666, null, "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
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

    @Test
    public void testForbidEncryptionUsageForECCKeys() throws Exception {
        // Given that ECDSA algorithm is used, and key encipherment and setKeyUsageForbidEncryption are selected in the Certificate Profile
        final CryptoToken cryptoToken = getNewCryptoToken();
        final KeyPair keypair = KeyTools.genKeys("brainpoolp224r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        final X509CA x509CA = createTestCA(cryptoToken, "CN=foo");
        final EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);

        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setKeyUsageForbidEncryption(true);
        certificateProfile.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);

        try {
            // Key Encipherment should not be true in the following certificate.
            X509Certificate certificate = (X509Certificate) x509CA.generateCertificate(cryptoToken, user, keypair.getPublic(), 0, null,
                                                                                       "10d", certificateProfile, "00000", cceConfig);

            assertNotNull("There should be a valid certificate", certificate);

            final boolean keyEncipherment = certificate.getKeyUsage()[CertificateConstants.KEYENCIPHERMENT];
            final boolean nonRepudation = certificate.getKeyUsage()[CertificateConstants.NONREPUDIATION];

            assertEquals("Key Encipherment key usage should be false", false, keyEncipherment);
            assertEquals("Non Repudation key usage should be true", true, nonRepudation);

        } catch (CAOfflineException e) {
            fail("Certificate could not be created or AIA could not be parsed: " + e.getMessage());
        }
    }

    private static ASN1Encodable getValueFromDN(Certificate cert, ASN1ObjectIdentifier oid) {
        final X500Principal principal = ((X509Certificate)cert).getSubjectX500Principal();
        final X500Name xname = X500Name.getInstance(principal.getEncoded());
        final RDN rdn = xname.getRDNs(oid)[0];
        return rdn.getTypesAndValues()[0].getValue();
    }


    private static KeyPair genTestKeyPair(String algName) throws InvalidAlgorithmParameterException {
        if (algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410)) {
            final String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("gost3410", "B");
            if (keyspec != null) {
                return KeyTools.genKeys(keyspec, AlgorithmConstants.KEYALGORITHM_ECGOST3410);
            } else {
                return null;
            }
        } else if(algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145)) {
            final String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("dstu4145", "233");
            if (keyspec != null) {
                return KeyTools.genKeys(keyspec, AlgorithmConstants.KEYALGORITHM_DSTU4145);
            } else {
                return null;
            }
        } else if(algName.equals(AlgorithmConstants.SIGALG_SHA1_WITH_DSA)) {
            return KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_DSA);
        } else if(algName.contains("ECDSA")) {
            return KeyTools.genKeys("brainpoolp224r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        } else if(algName.equals(AlgorithmConstants.SIGALG_ED25519)) {
            return KeyTools.genKeys("Ed25519", AlgorithmConstants.KEYALGORITHM_ED25519);
        } else if(algName.equals(AlgorithmConstants.SIGALG_DILITHIUM3)) {
            return KeyTools.genKeys(AlgorithmConstants.KEYALGORITHM_DILITHIUM3, AlgorithmConstants.KEYALGORITHM_DILITHIUM3);
        } else if(algName.equals(AlgorithmConstants.SIGALG_FALCON512)) {
            return KeyTools.genKeys(AlgorithmConstants.SIGALG_FALCON512, AlgorithmConstants.SIGALG_FALCON512);
        } else {
            return KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        }
    }

}
