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

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Properties;

import org.cesecore.RoleUsingTestCase;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ConstructionException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the CA session bean using soft CA tokens.
 * 
 * @version $Id$
 */
public class CaSessionTest extends RoleUsingTestCase {

    private static final String X509CADN = "CN=TEST";
    private static final String CVCCADN = "CN=TEST001,C=SE";
    private static CA testx509ca;
    private static CA testcvcca;

    private static CaSessionTestBase testBase;

    private static final String UTIMACO_PKCS11_LINUX_LIB = "/etc/utimaco/libcs2_pkcs11.so";
    private static final String UTIMACO_PKCS11_WINDOWS_LIB = "C:/Program Files/Utimaco/SafeGuard CryptoServer/Lib/cs2_pkcs11.dll";
    private static final String LUNASA_PKCS11_LINUX_LIB = "/usr/lunasa/lib/libCryptoki2_64.so";
    private static final String PROTECTSERVER_PKCS11_LINUX_LIB = "/opt/ETcpsdk/lib/linux-x86_64/libcryptoki.so";

    @BeforeClass
    public static void setUpProviderAndCreateCA() throws Exception {
        CryptoProviderTools.installBCProvider();
        testx509ca = CaSessionTest.createTestX509CA(X509CADN, null, false);
        testcvcca = CaSessionTest.createTestCVCCA(CVCCADN, null, false);
        testBase = new CaSessionTestBase(testx509ca, testcvcca);
    }

    @Before
    public void setUp() throws Exception {
        testBase.setUp();
    }

    @After
    public void tearDown() throws Exception {
        testBase.tearDown();
    }

    @Test
    public void testAddRenameAndRemoveX509CA() throws Exception {
        testBase.testAddRenameAndRemoveX509CA();
    }

    @Test
    public void testAddAndGetCAWithDifferentCaid() throws Exception {
        testBase.testAddAndGetCAWithDifferentCaid();
    }

    @Test
    public void testAddRenameAndRemoveCVCCA() throws Exception {
        testBase.testAddRenameAndRemoveCVCCA();
    }

    @Test
    public void addCAGenerateKeysLater() throws Exception {
        final String cadn = "CN=TEST GEN KEYS, O=CaSessionTest, C=SE";
        final String tokenpwd = "thisisatest";
        CA ca = CaSessionTest.createTestX509CAOptionalGenKeys(cadn, tokenpwd, false, false);
        testBase.addCAGenerateKeysLater(ca, cadn, tokenpwd);
    }

// We don't use the CryptoTokenSession in EJBCA
//    @Test
//    public void addCAUseSessionBeanToGenerateKeys() throws Exception {
//        final String cadn = "CN=TEST GEN KEYS, O=CaSessionTest, C=SE";
//        final String tokenpwd = "thisisatest";
//        CA ca = CaSessionTest.createTestX509CAOptionalGenKeys(cadn, tokenpwd, false, false);
//        testBase.addCAUseSessionBeanToGenerateKeys(ca, cadn, tokenpwd);
//    }

    @Test
    public void addCAUseSessionBeanToGenerateKeys2() throws Exception {
        final String cadn = "CN=TEST GEN KEYS, O=CaSessionTest, C=SE";
        final String tokenpwd = "thisisatest";
        CA ca = createTestX509CAOptionalGenKeys(cadn, tokenpwd, false, false);
        testBase.addCAUseSessionBeanToGenerateKeys2(ca, cadn, tokenpwd);
    }

    @Test
    public void testExtendedCAService() throws Exception {
        CA ca = createTestX509CAOptionalGenKeys("CN=Test Extended CA servoce", "foo123", false, false);
        testBase.extendedCAServices(ca);
    }

    @Test
    public void testAuthorization() throws Exception {
        testBase.testAuthorization();
    }

    public static X509CA createTestX509CA(String cadn, String tokenpin, boolean pkcs11) throws Exception {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11);
    }

    public static X509CA createTestX509CAOptionalGenKeys(String cadn, String tokenpin, boolean genKeys, boolean pkcs11) throws Exception {
        // Create catoken
        CryptoToken cryptoToken = createCryptoToken(tokenpin, pkcs11);
        if (genKeys) {
            cryptoToken.generateKeyPair("512", CAToken.SOFTPRIVATESIGNKEYALIAS);
            cryptoToken.generateKeyPair("512", CAToken.SOFTPRIVATEDECKEYALIAS);
        }

        CAToken catoken = new CAToken(cryptoToken);
        catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        // Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
        catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);

        CATokenInfo catokeninfo = catoken.getTokenInfo();
        // No extended services
        ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();

        X509CAInfo cainfo = new X509CAInfo(cadn, "TEST", CAConstants.CA_ACTIVE, new Date(), "", CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA,
                3650, null, // Expiretime
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
                null, // Authority Information Access
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
                null // cmpRaAuthSecret
        );

        X509CA x509ca = new X509CA(cainfo);
        x509ca.setCAToken(catoken);
        // A CA certificate
        Collection<Certificate> cachain = new ArrayList<Certificate>();
        if (genKeys) {
            X509Certificate cacert = CertTools.genSelfCert(cadn, 10L, "1.1.1.1", catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN),
                    catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), "SHA256WithRSA", true, catoken.getCryptoToken()
                            .getSignProviderName());
            assertNotNull(cacert);
            cachain.add(cacert);
        }
        x509ca.setCertificateChain(cachain);
        // Now our CA should be operational, if we generated keys, otherwise we will have to generate is, and a CA certificate later.
        return x509ca;
    }

    public static CryptoToken createCryptoToken(String tokenpin, boolean pkcs11) throws CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException {
        Properties prop = new Properties();
        prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        // Set key generation property, since we have no old keys to generate the same sort
        prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, "512");
        if (tokenpin != null) {
            prop.setProperty(SoftCryptoToken.NODEFAULTPWD, "true");
        }
        CryptoToken cryptoToken;
        if (pkcs11) {
            String hsmlib = getHSMLibrary();
            assertNotNull(hsmlib);
            prop.setProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, hsmlib);
            prop.setProperty(PKCS11CryptoToken.SLOT_LABEL_KEY, "1");
            cryptoToken = CryptoTokenFactory.createCryptoToken(PKCS11CryptoToken.class.getName(), prop, null, 666);
        } else {
            cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), prop, null, 666);
        }
        if (tokenpin != null) {
            cryptoToken.activate(tokenpin.toCharArray());
        }
        return cryptoToken;
    }

    protected static CVCCA createTestCVCCA(String cadn, String tokenpin, boolean pkcs11) throws Exception {
        // Create catoken
        CryptoToken cryptoToken = createCryptoToken(tokenpin, pkcs11);
        cryptoToken.generateKeyPair("512", CAToken.SOFTPRIVATESIGNKEYALIAS);
        cryptoToken.generateKeyPair("512", CAToken.SOFTPRIVATEDECKEYALIAS);

        CAToken catoken = new CAToken(cryptoToken);
        // Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
        catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);

        CATokenInfo catokeninfo = catoken.getTokenInfo();
        // No extended services
        ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();

        CVCCAInfo cainfo = new CVCCAInfo(cadn, "TESTCVC", CAConstants.CA_ACTIVE, new Date(), CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA,
                3650, null, // Expiretime
                CAInfo.CATYPE_CVC, CAInfo.SELFSIGNED, (Collection<Certificate>) null, catokeninfo, "JUnit RSA CVC CA", -1, null, 24, // CRLPeriod
                0, // CRLIssueInterval
                10, // CRLOverlapTime
                10, // Delta CRL period
                new ArrayList<Integer>(), true, // Finish User
                extendedcaservices, new ArrayList<Integer>(), // Approvals Settings
                1, // Number of Req approvals
                true, // includeInHelathCheck
                true, // isDoEnforceUniquePublicKeys
                true, // isDoEnforceUniqueDistinguishedName
                false, // isDoEnforceUniqueSubjectDNSerialnumber
                true, // useCertReqHistory
                true, // useUserStorage
                true // useCertificateStorage
        );

        CVCCA cvcca = new CVCCA(cainfo);
        cvcca.setCAToken(catoken);
        // A CA certificate
        CAReferenceField caRef = new CAReferenceField("SE", "CAREF001", "00000");
        HolderReferenceField holderRef = new HolderReferenceField("SE", "CAREF001", "00000");
        CVCertificate cv = createTestCvcCertificate(catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN),
                catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), caRef, holderRef, "SHA256WithRSA", AuthorizationRoleEnum.CVCA,
                cryptoToken.getSignProviderName());
        CardVerifiableCertificate cvccacert = new CardVerifiableCertificate(cv);
        Certificate cacert = cvccacert;
        assertNotNull(cacert);
        Collection<Certificate> cachain = new ArrayList<Certificate>();
        cachain.add(cacert);
        cvcca.setCertificateChain(cachain);
        // Now our CA should be operational
        return cvcca;
    }

    private static CVCertificate createTestCvcCertificate(PublicKey publicKey, PrivateKey privateKey, CAReferenceField caRef,
            HolderReferenceField holderRef, String algorithm, AuthorizationRoleEnum role, String provider) throws IOException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, ConstructionException {
        // Skapa default-datum
        Calendar cal1 = Calendar.getInstance();
        Date validFrom = cal1.getTime();

        Calendar cal2 = Calendar.getInstance();
        cal2.add(Calendar.MONTH, 3);
        Date validTo = cal2.getTime();
        return CertificateGenerator.createCertificate(publicKey, privateKey, algorithm, caRef, holderRef, role,
                AccessRightEnum.READ_ACCESS_DG3_AND_DG4, validFrom, validTo, provider);
    }

    private static String getHSMLibrary() {
        final File utimacoCSLinux = new File(UTIMACO_PKCS11_LINUX_LIB);
        final File utimacoCSWindows = new File(UTIMACO_PKCS11_WINDOWS_LIB);
        final File lunaSALinux64 = new File(LUNASA_PKCS11_LINUX_LIB);
        final File protectServerLinux64 = new File(PROTECTSERVER_PKCS11_LINUX_LIB);
        String ret = null;
        if (utimacoCSLinux.exists()) {
            ret = utimacoCSLinux.getAbsolutePath();
        } else if (utimacoCSWindows.exists()) {
            ret = utimacoCSWindows.getAbsolutePath();
        } else if (lunaSALinux64.exists()) {
            ret = lunaSALinux64.getAbsolutePath();
        } else if (protectServerLinux64.exists()) {
            ret = protectServerLinux64.getAbsolutePath();
        }
        return ret;
    }

}
