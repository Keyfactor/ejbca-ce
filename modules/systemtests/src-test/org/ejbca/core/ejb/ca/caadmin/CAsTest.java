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

package org.ejbca.core.ejb.ca.caadmin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CVCCAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaTestSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderRemote;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.protocol.cmp.CmpResponseMessage;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the ca data entity bean.
 * 
 * @version $Id$
 */
public class CAsTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(CAsTest.class);
    private static final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private CaTestSessionRemote caTestSession = JndiHelper.getRemoteSession(CaTestSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private CertificateProfileSessionRemote certificateProfileSession = InterfaceCache.getCertificateProfileSession();
    private SimpleAuthenticationProviderRemote simpleAuthenticationProvider = JndiHelper.getRemoteSession(SimpleAuthenticationProviderRemote.class);

    // private AuthenticationToken adminTokenNoAuth;

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();

    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * adds a CA using RSA keys to the database.
     * 
     * It also checks that the CA is stored correctly.
     * 
     * @throws Exception error
     */
    @Test
    public void test01AddRSACA() throws Exception {

        final String caName = getTestCAName();

        // Preemptively remove the CA if it exists.
        try {
            CA ca = caTestSession.getCA(caAdmin, caName);
            caSession.removeCA(caAdmin, ca.getCAId());
        } catch (CADoesntExistsException e) {
            // All is well, do go on.
        }

        // TODO: do we need init here? We should run the system tests on a "base installed" system
        // adminGroupSession.init(admin, getTestCAId(), DEFAULT_SUPERADMIN_CN);
        CATokenInfo catokeninfo = new CATokenInfo();
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catokeninfo.setClassPath(SoftCryptoToken.class.getName());

        Properties prop = catokeninfo.getProperties();
        // Set some CA token properties if they are not set already
        if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
            prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf("1024"));
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        }
        catokeninfo.setProperties(prop);

        // Create and active OSCP CA Service.
        ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, " + "CN=TEST", "", "1024",
                AlgorithmConstants.KEYALGORITHM_RSA));

        X509CAInfo cainfo = new X509CAInfo("CN=TEST", caName, SecConst.CA_ACTIVE, new Date(), "", SecConst.CERTPROFILE_FIXED_ROOTCA, 3650, null, // Expiretime
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
                null // cmpRaAuthSecret
        );

        caAdminSession.createCA(caAdmin, cainfo);

        CAInfo info = caSession.getCAInfo(caAdmin, getTestCAName());

        Collection<Certificate> rootcacertchain = info.getCertificateChain();
        X509Certificate cert = (X509Certificate) rootcacertchain.iterator().next();
        String sigAlg = AlgorithmTools.getSignatureAlgorithm(cert);
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, sigAlg);
        assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals("CN=TEST"));
        assertTrue("Creating CA failed", info.getSubjectDN().equals("CN=TEST"));
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey rsapk = (RSAPublicKey) pk;
            assertEquals(rsapk.getAlgorithm(), "RSA");
        } else {
            assertTrue("Public key is not EC", false);
        }
        assertTrue(
                "CA is not valid for the specified duration.",
                cert.getNotAfter().after(new Date(new Date().getTime() + 10 * 364 * 24 * 60 * 60 * 1000L))
                        && cert.getNotAfter().before(new Date(new Date().getTime() + 10 * 366 * 24 * 60 * 60 * 1000L)));

        // Test to generate a certificate request from the CA
        Collection<Certificate> cachain = info.getCertificateChain();
        byte[] request = caAdminSession.makeRequest(caAdmin, info.getCAId(), cachain, false, false, false, null);
        PKCS10RequestMessage msg = new PKCS10RequestMessage(request);
        assertEquals("CN=TEST", msg.getRequestDN());

        // Check CMP RA secret, default value empty string
        X509CAInfo xinfo = (X509CAInfo) info;
        assertNotNull(xinfo.getCmpRaAuthSecret());
        assertEquals("", xinfo.getCmpRaAuthSecret());

    }

    /**
     * renames CA in database.
     * 
     * @throws Exception error
     */
    @Test
    public void test02RenameCA() throws Exception {
        log.trace(">test02RenameCA()");

        boolean ret = false;
        try {
            caSession.renameCA(admin, getTestCAName(), "TEST2");
            caSession.renameCA(admin, "TEST2", getTestCAName());
            ret = true;
        } catch (CAExistsException cee) {
        }
        assertTrue("Renaming CA failed", ret);

        log.trace("<test02RenameCA()");
    }

    /**
     * edits ca and checks that it's stored correctly.
     * 
     * @throws Exception error
     */
    @Test
    public void test03EditCA() throws Exception {
        log.trace(">test03EditCA()");

        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(admin, getTestCAName());
        info.setCRLPeriod(33);
        caAdminSession.editCA(admin, info);
        X509CAInfo info2 = (X509CAInfo) caSession.getCAInfo(admin, getTestCAName());
        assertTrue("Editing CA failed", info2.getCRLPeriod() == 33);

        log.trace("<test03EditCA()");
    }

    /**
     * adds a CA Using ECDSA keys to the database.
     * 
     * It also checks that the CA is stored correctly.
     * 
     * @throws Exception error
     */
    @Test
    public void test04AddECDSACA() throws Exception {

        boolean ret = false;
        try {
            // TODO: is init needed? We should run the system tests on a base installed system
            // adminGroupSession.init(admin, "CN=TESTECDSA".hashCode(), DEFAULT_SUPERADMIN_CN);

            CATokenInfo catokeninfo = new CATokenInfo();
            catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
            catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
            catokeninfo.setClassPath(SoftCryptoToken.class.getName());
            catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
            catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            // Create and active OSCP CA Service.
            ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSSignerCertificate, " + "CN=TESTECDSA", "",
                    "prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA));

            ArrayList<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
            policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));

            Properties prop = catokeninfo.getProperties();
            // Set some CA token properties if they are not set already
            if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
                prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf("prime192v1"));
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
            }
            catokeninfo.setProperties(prop);

            X509CAInfo cainfo = new X509CAInfo("CN=TESTECDSA", "TESTECDSA", SecConst.CA_ACTIVE, new Date(), "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                    365, null, // Expiretime
                    CAInfo.CATYPE_X509, CAInfo.SELFSIGNED, (Collection<Certificate>) null, catokeninfo, "JUnit ECDSA CA", -1, null, policies, // PolicyId
                    24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    0, // Delta CRL period
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
                    true, // include in Health Check
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true, // useCertificateStorage
                    null // cmpRaAuthSecret
            );

            removeOldCa("TESTECDSA");

            caAdminSession.createCA(admin, cainfo);

            CAInfo info = caSession.getCAInfo(admin, "TESTECDSA");

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            String sigAlg = AlgorithmTools.getSignatureAlgorithm(cert);
            assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, sigAlg);
            assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals("CN=TESTECDSA"));
            assertTrue("Creating CA failed", info.getSubjectDN().equals("CN=TESTECDSA"));
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof JCEECPublicKey) {
                JCEECPublicKey ecpk = (JCEECPublicKey) pk;
                assertEquals(ecpk.getAlgorithm(), "EC");
                org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
                assertNotNull("ImplicitlyCA must have null spec", spec);
            } else {
                assertTrue("Public key is not EC", false);
            }

            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
            fail("Creating ECDSA CA failed because CA exists.");
        }

        assertTrue("Creating ECDSA CA failed", ret);
    }

    /**
     * adds a CA Using ECDSA 'implicitlyCA' keys to the database.
     * 
     * It also checks that the CA is stored correctly.
     * 
     * @throws Exception error
     */
    @Test
    public void test05AddECDSAImplicitlyCACA() throws Exception {
        log.trace(">test05AddECDSAImplicitlyCACA()");
        boolean ret = false;

        removeOldCa("TESTECDSAImplicitlyCA");

        try {
            // TODO: do we need init here? we should run the system tests on a base installed system
            // adminGroupSession.init(admin, "CN=TESTECDSAImplicitlyCA".hashCode(), DEFAULT_SUPERADMIN_CN);

            CATokenInfo catokeninfo = new CATokenInfo();
            catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
            catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
            catokeninfo.setClassPath(SoftCryptoToken.class.getName());
            catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
            catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);

            Properties prop = catokeninfo.getProperties();
            // Set some CA token properties if they are not set already
            if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
                prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf("implicitlyCA"));
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
            }
            catokeninfo.setProperties(prop);

            // Create and active OSCP CA Service.
            ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));

            extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, " + "CN=TESTECDSAImplicitlyCA",
                    "", "prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA));

            ArrayList<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
            policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));

            X509CAInfo cainfo = new X509CAInfo("CN=TESTECDSAImplicitlyCA", "TESTECDSAImplicitlyCA", SecConst.CA_ACTIVE, new Date(), "",
                    SecConst.CERTPROFILE_FIXED_ROOTCA, 365,
                    null, // Expiretime
                    CAInfo.CATYPE_X509, CAInfo.SELFSIGNED, (Collection<Certificate>) null, catokeninfo, "JUnit ECDSA ImplicitlyCA CA", -1, null,
                    policies, // PolicyId
                    24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    0, // Delta CRL period
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
                    true, // Include in healthCheck
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true, // useCertificateStorage
                    null // cmpRaAuthSecret
            );

            caAdminSession.createCA(admin, cainfo);

            CAInfo info = caSession.getCAInfo(admin, "TESTECDSAImplicitlyCA");

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals("CN=TESTECDSAImplicitlyCA"));
            assertTrue("Creating CA failed", info.getSubjectDN().equals("CN=TESTECDSAImplicitlyCA"));
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof JCEECPublicKey) {
                JCEECPublicKey ecpk = (JCEECPublicKey) pk;
                assertEquals(ecpk.getAlgorithm(), "EC");
                ECParameterSpec spec = ecpk.getParameters();
                assertNull("ImplicitlyCA must have null spec, because it should be explicitly set in ejbca.properties", spec);

            } else {
                assertTrue("Public key is not EC", false);
            }

            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }

        assertTrue("Creating ECDSA ImplicitlyCA CA failed", ret);
        log.trace("<test05AddECDSAImplicitlyCACA()");
    }

    /**
     * adds a CA using RSA keys to the database.
     * 
     * It also checks that the CA is stored correctly.
     * 
     * @throws Exception error
     */
    @Test
    public void test06AddRSASha256WithMGF1CA() throws Exception {
        log.trace(">test06AddRSASha256WithMGF1CA()");

        removeOldCa("TESTSha256WithMGF1");

        boolean ret = false;
        try {
            String cadn = "CN=TESTSha256WithMGF1";
            // adminGroupSession.init(admin, cadn.hashCode(), DEFAULT_SUPERADMIN_CN);

            CATokenInfo catokeninfo = new CATokenInfo();
            catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
            catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
            catokeninfo.setClassPath(SoftCryptoToken.class.getName());
            catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1);
            catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1);
            // Create and active OSCP CA Service.
            ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, " + cadn, "", "1024",
                    AlgorithmConstants.KEYALGORITHM_RSA));

            Properties prop = catokeninfo.getProperties();
            // Set some CA token properties if they are not set already
            if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
                prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf("1024"));
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
            }
            catokeninfo.setProperties(prop);

            X509CAInfo cainfo = new X509CAInfo(cadn, "TESTSha256WithMGF1", SecConst.CA_ACTIVE, new Date(), "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                    365, null, // Expiretime
                    CAInfo.CATYPE_X509, CAInfo.SELFSIGNED, (Collection<Certificate>) null, catokeninfo, "JUnit RSA CA", -1, null, null, // PolicyId
                    24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    0, // Delta CRL period
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
                    true, // Include in healthCheck
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true, // useCertificateStorage
                    null // cmpRaAuthSecret
            );
            caAdminSession.createCA(admin, cainfo);

            CAInfo info = caSession.getCAInfo(admin, "TESTSha256WithMGF1");

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            String sigAlg = AlgorithmTools.getSignatureAlgorithm(cert);
            assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, sigAlg);
            assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals(cadn));
            assertTrue("Creating CA failed", info.getSubjectDN().equals(cadn));
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof RSAPublicKey) {
                RSAPublicKey rsapk = (RSAPublicKey) pk;
                assertEquals(rsapk.getAlgorithm(), "RSA");
            } else {
                assertTrue("Public key is not RSA", false);
            }

            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }

        assertTrue("Creating RSA CA failed", ret);
        log.trace("<test06AddRSASha256WithMGF1CA()");
    }

    @Test
    public void test07AddRSACA4096() throws Exception {
        log.trace(">test07AddRSACA4096()");

        removeOldCa("TESTRSA4096");

        boolean ret = false;
        try {
            String dn = CertTools
                    .stringToBCDNString("CN=TESTRSA4096,OU=FooBaaaaaar veeeeeeeery long ou,OU=Another very long very very long ou,O=FoorBar Very looong O,L=Lets ad a loooooooooooooooooong Locality as well,C=SE");
            // adminGroupSession.init(admin, dn.hashCode(), DEFAULT_SUPERADMIN_CN);

            CATokenInfo catokeninfo = new CATokenInfo();
            catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
            catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
            catokeninfo.setClassPath(SoftCryptoToken.class.getName());
            catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
            catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            // Create and active OSCP CA Service.
            ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, " + dn, "", "2048",
                    AlgorithmConstants.KEYALGORITHM_RSA));

            Properties prop = catokeninfo.getProperties();
            // Set some CA token properties if they are not set already
            if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
                prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf("1024"));
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
            }
            catokeninfo.setProperties(prop);

            X509CAInfo cainfo = new X509CAInfo(
                    dn,
                    "TESTRSA4096",
                    SecConst.CA_ACTIVE,
                    new Date(),
                    "",
                    SecConst.CERTPROFILE_FIXED_ROOTCA,
                    365,
                    null, // Expiretime
                    CAInfo.CATYPE_X509,
                    CAInfo.SELFSIGNED,
                    (Collection<Certificate>) null,
                    catokeninfo,
                    "JUnit RSA CA, we ned also a very long CA description for this CA, because we want to create a CA Data string that is more than 36000 characters or something like that. All this is because Oracle can not set very long strings with the JDBC provider and we must test that we can handle long CAs",
                    -1, null, null, // PolicyId
                    24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    0, // Delta CRL period
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
                    true, // Include in HealthCheck
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true, // useCertificateStorage
                    null // cmpRaAuthSecret
            );

            caAdminSession.createCA(admin, cainfo);

            CAInfo info = caSession.getCAInfo(admin, "TESTRSA4096");

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            String sigAlg = AlgorithmTools.getSignatureAlgorithm(cert);
            assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, sigAlg);
            assertTrue("Error in created ca certificate", CertTools.stringToBCDNString(cert.getSubjectDN().toString()).equals(dn));
            assertTrue("Creating CA failed", info.getSubjectDN().equals(dn));
            // Normal order
            assertEquals(
                    cert.getSubjectX500Principal().getName(),
                    "C=SE,L=Lets ad a loooooooooooooooooong Locality as well,O=FoorBar Very looong O,OU=Another very long very very long ou,OU=FooBaaaaaar veeeeeeeery long ou,CN=TESTRSA4096");
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof RSAPublicKey) {
                RSAPublicKey rsapk = (RSAPublicKey) pk;
                assertEquals(rsapk.getAlgorithm(), "RSA");
            } else {
                assertTrue("Public key is not EC", false);
            }

            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }

        assertTrue("Creating RSA CA 4096 failed", ret);
        log.trace("<test07AddRSACA4096()");
    }

    @Test
    public void test08AddRSACAReverseDN() throws Exception {

        removeOldCa("TESTRSAREVERSE");

        log.trace(">test08AddRSACAReverseDN()");
        boolean ret = false;
        try {
            String dn = CertTools.stringToBCDNString("CN=TESTRSAReverse,O=FooBar,OU=BarFoo,C=SE");
            String name = "TESTRSAREVERSE";
            // adminGroupSession.init(admin, dn.hashCode(), DEFAULT_SUPERADMIN_CN);

            CATokenInfo catokeninfo = new CATokenInfo();
            catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
            catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
            catokeninfo.setClassPath(SoftCryptoToken.class.getName());
            catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            // Create and active OSCP CA Service.
            ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, " + dn, "", "1024",
                    AlgorithmConstants.KEYALGORITHM_RSA));

            Properties prop = catokeninfo.getProperties();
            // Set some CA token properties if they are not set already
            if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
                prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf("1024"));
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
            }
            catokeninfo.setProperties(prop);

            X509CAInfo cainfo = new X509CAInfo(
                    dn,
                    name,
                    SecConst.CA_ACTIVE,
                    new Date(),
                    "",
                    SecConst.CERTPROFILE_FIXED_ROOTCA,
                    365,
                    null, // Expiretime
                    CAInfo.CATYPE_X509,
                    CAInfo.SELFSIGNED,
                    (Collection<Certificate>) null,
                    catokeninfo,
                    "JUnit RSA CA, we ned also a very long CA description for this CA, because we want to create a CA Data string that is more than 36000 characters or something like that. All this is because Oracle can not set very long strings with the JDBC provider and we must test that we can handle long CAs",
                    -1, null, null, // PolicyId
                    24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    0, // Delta CRL period
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
                    false, // Use X500 DN order
                    false, // Use CRL Distribution Point on CRL
                    false, // CRL Distribution Point on CRL critical
                    true, // Include in health check
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true, // useCertificateStorage
                    null // cmpRaAuthSecret
            );

            caAdminSession.createCA(admin, cainfo);

            CAInfo info = caSession.getCAInfo(admin, name);

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            String sigAlg = AlgorithmTools.getSignatureAlgorithm(cert);
            assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, sigAlg);
            assertEquals("Error in created ca certificate", CertTools.stringToBCDNString(cert.getSubjectDN().toString()), dn);
            assertTrue("Creating CA failed", info.getSubjectDN().equals(dn));
            // reverse order
            assertEquals(cert.getSubjectX500Principal().getName(), "CN=TESTRSAReverse,OU=BarFoo,O=FooBar,C=SE");
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof RSAPublicKey) {
                RSAPublicKey rsapk = (RSAPublicKey) pk;
                assertEquals(rsapk.getAlgorithm(), "RSA");
            } else {
                assertTrue("Public key is not EC", false);
            }

            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }

        assertTrue("Creating RSA CA reverse failed", ret);
        log.trace("<test08AddRSACAReverseDN()");
    }

    @Test
    public void test09AddCVCCARSA() throws Exception {
        removeOldCa("TESTDV-D");
        removeOldCa("TESTCVCA");
        removeOldCa("TESTDV-F");
        certificateProfileSession.removeCertificateProfile(admin, "TESTCVCDV");

        boolean ret = false;
        CATokenInfo catokeninfo = new CATokenInfo();
        catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catokeninfo.setClassPath(SoftCryptoToken.class.getName());
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1);
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1);
        // No CA Services.
        ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();

        Properties prop = catokeninfo.getProperties();
        // Set some CA token properties if they are not set already
        if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
            prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf("1024"));
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        }
        catokeninfo.setProperties(prop);

        String rootcadn = "CN=TESTCVCA,C=SE";
        String rootcaname = "TESTCVCA";
        String dvddn = "CN=TESTDV-D,C=SE";
        String dvdcaname = "TESTDV-D";
        String dvfdn = "CN=TESTDV-F,C=FI";
        String dvfcaname = "TESTDV-F";

        CAInfo dvdcainfo = null; // to be used for renewal
        CAInfo cvcainfo = null; // to be used for making request

        // Create a root CVCA
        try {
            // adminGroupSession.init(admin, rootcadn.hashCode(), DEFAULT_SUPERADMIN_CN);

            CVCCAInfo cvccainfo = new CVCCAInfo(rootcadn, rootcaname, SecConst.CA_ACTIVE, new Date(), SecConst.CERTPROFILE_FIXED_ROOTCA, 3650, null, // Expiretime
                    CAInfo.CATYPE_CVC, CAInfo.SELFSIGNED, null, catokeninfo, "JUnit CVC CA", -1, null, 24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    10, // Delta CRL period
                    new ArrayList<Integer>(), // CRL publishers
                    true, // Finish User
                    extendedcaservices, new ArrayList<Integer>(), // Approvals Settings
                    1, // Number of Req approvals
                    true, // Include in health check
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true // useCertificateStorage
            );

            caAdminSession.createCA(admin, cvccainfo);

            cvcainfo = caSession.getCAInfo(admin, rootcaname);
            assertEquals(CAInfo.CATYPE_CVC, cvcainfo.getCAType());

            Certificate cert = (Certificate) cvcainfo.getCertificateChain().iterator().next();
            String sigAlg = AlgorithmTools.getSignatureAlgorithm(cert);
            assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, sigAlg);
            assertEquals("CVC", cert.getType());
            assertEquals(rootcadn, CertTools.getSubjectDN(cert));
            assertEquals(rootcadn, CertTools.getIssuerDN(cert));
            assertEquals(rootcadn, cvcainfo.getSubjectDN());
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof RSAPublicKey) {
                RSAPublicKey rsapk = (RSAPublicKey) pk;
                assertEquals(rsapk.getAlgorithm(), "RSA");
                BigInteger modulus = rsapk.getModulus();
                int len = modulus.bitLength();
                assertEquals(1024, len);
            } else {
                assertTrue("Public key is not RSA", false);
            }
            assertTrue("CA is not valid for the specified duration.",
                    CertTools.getNotAfter(cert).after(new Date(new Date().getTime() + 10 * 364 * 24 * 60 * 60 * 1000L))
                            && CertTools.getNotAfter(cert).before(new Date(new Date().getTime() + 10 * 366 * 24 * 60 * 60 * 1000L)));
            // Check role
            CardVerifiableCertificate cvcert = (CardVerifiableCertificate) cert;
            String role = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
            assertEquals("SETESTCVCA00001", cvcert.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated());
            assertEquals("CVCA", role);
            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }
        assertTrue(ret);

        // Create a Sub DV domestic
        ret = false;
        try {
            // adminGroupSession.init(admin, dvddn.hashCode(), DEFAULT_SUPERADMIN_CN);
            // Create a Certificate profile
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
            certificateProfileSession.addCertificateProfile(admin, "TESTCVCDV", profile);
            int profileid = certificateProfileSession.getCertificateProfileId("TESTCVCDV");

            CVCCAInfo cvccainfo = new CVCCAInfo(dvddn, dvdcaname, SecConst.CA_ACTIVE, new Date(), profileid, 3650, null, // Expiretime
                    CAInfo.CATYPE_CVC, rootcadn.hashCode(), null, catokeninfo, "JUnit CVC CA", -1, null, 24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    10, // Delta CRL period
                    new ArrayList<Integer>(), // CRL publishers
                    true, // Finish User
                    extendedcaservices, new ArrayList<Integer>(), // Approvals Settings
                    1, // Number of Req approvals
                    true, // Include in health check
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true // useCertificateStorage
            );

            caAdminSession.createCA(admin, cvccainfo);

            dvdcainfo = caSession.getCAInfo(admin, dvdcaname);
            assertEquals(CAInfo.CATYPE_CVC, dvdcainfo.getCAType());

            Certificate cert = (Certificate) dvdcainfo.getCertificateChain().iterator().next();
            assertEquals("CVC", cert.getType());
            assertEquals(CertTools.getSubjectDN(cert), dvddn);
            assertEquals(CertTools.getIssuerDN(cert), rootcadn);
            assertEquals(dvdcainfo.getSubjectDN(), dvddn);
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof RSAPublicKey) {
                RSAPublicKey rsapk = (RSAPublicKey) pk;
                assertEquals(rsapk.getAlgorithm(), "RSA");
                BigInteger modulus = rsapk.getModulus();
                int len = modulus.bitLength();
                assertEquals(1024, len);
            } else {
                assertTrue("Public key is not RSA", false);
            }
            assertTrue("CA is not valid for the specified duration.",
                    CertTools.getNotAfter(cert).after(new Date(new Date().getTime() + 10 * 364 * 24 * 60 * 60 * 1000L))
                            && CertTools.getNotAfter(cert).before(new Date(new Date().getTime() + 10 * 366 * 24 * 60 * 60 * 1000L)));
            // Check role
            CardVerifiableCertificate cvcert = (CardVerifiableCertificate) cert;
            assertEquals("SETESTDV-D00001", cvcert.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated());
            String role = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
            assertEquals("DV_D", role);
            String accessRights = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAccessRight()
                    .name();
            assertEquals("READ_ACCESS_DG3_AND_DG4", accessRights);
            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }
        assertTrue(ret);

        // Create a Sub DV foreign
        ret = false;
        try {
            // adminGroupSession.init(admin, dvfdn.hashCode(), DEFAULT_SUPERADMIN_CN);

            CVCCAInfo cvccainfo = new CVCCAInfo(dvfdn, dvfcaname, SecConst.CA_ACTIVE, new Date(), SecConst.CERTPROFILE_FIXED_SUBCA, 3650, null, // Expiretime
                    CAInfo.CATYPE_CVC, rootcadn.hashCode(), null, catokeninfo, "JUnit CVC CA", -1, null, 24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    10, // Delta CRL period
                    new ArrayList<Integer>(), // CRL publishers
                    true, // Finish User
                    extendedcaservices, new ArrayList<Integer>(), // Approvals Settings
                    1, // Number of Req approvals
                    true, // Include in health check
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true // useCertificateStorage
            );

            caAdminSession.createCA(admin, cvccainfo);

            CAInfo info = caSession.getCAInfo(admin, dvfcaname);
            assertEquals(CAInfo.CATYPE_CVC, info.getCAType());

            Certificate cert = (Certificate) info.getCertificateChain().iterator().next();
            assertEquals("CVC", cert.getType());
            assertEquals(CertTools.getSubjectDN(cert), dvfdn);
            assertEquals(CertTools.getIssuerDN(cert), rootcadn);
            assertEquals(info.getSubjectDN(), dvfdn);
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof RSAPublicKey) {
                RSAPublicKey rsapk = (RSAPublicKey) pk;
                assertEquals(rsapk.getAlgorithm(), "RSA");
                BigInteger modulus = rsapk.getModulus();
                int len = modulus.bitLength();
                assertEquals(1024, len);
            } else {
                assertTrue("Public key is not RSA", false);
            }
            assertTrue("CA is not valid for the specified duration.",
                    CertTools.getNotAfter(cert).after(new Date(new Date().getTime() + 10 * 364 * 24 * 60 * 60 * 1000L))
                            && CertTools.getNotAfter(cert).before(new Date(new Date().getTime() + 10 * 366 * 24 * 60 * 60 * 1000L)));
            // Check role
            CardVerifiableCertificate cvcert = (CardVerifiableCertificate) cert;
            assertEquals("FITESTDV-F00001", cvcert.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated());
            String role = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
            assertEquals("DV_F", role);
            ret = true;
        } catch (CAExistsException pee) {
            log.info("CVC CA exists.");
            fail("CVC CA exists");
        }
        assertTrue("Creating CVC CAs failed", ret);

        // Test to renew a CVC CA using a different access right
        CertificateProfile profile = certificateProfileSession.getCertificateProfile("TESTCVCDV");
        profile.setCVCAccessRights(CertificateProfile.CVC_ACCESS_DG3);
        certificateProfileSession.changeCertificateProfile(admin, "TESTCVCDV", profile);

        int caid = dvdcainfo.getCAId();
        caAdminSession.renewCA(admin, caid, null, false);
        dvdcainfo = caSession.getCAInfo(admin, dvdcaname);
        assertEquals(CAInfo.CATYPE_CVC, dvdcainfo.getCAType());
        Certificate cert = (Certificate) dvdcainfo.getCertificateChain().iterator().next();
        assertEquals("CVC", cert.getType());
        assertEquals(CertTools.getSubjectDN(cert), dvddn);
        assertEquals(CertTools.getIssuerDN(cert), rootcadn);
        assertEquals(dvdcainfo.getSubjectDN(), dvddn);
        // It's not possible to check the time for renewal of a CVC CA since the
        // resolution of validity is only days.
        // The only way is to generate a certificate with different access
        // rights in it
        CardVerifiableCertificate cvcert = (CardVerifiableCertificate) cert;
        String role = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
        assertEquals("DV_D", role);
        String accessRights = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAccessRight()
                .name();
        assertEquals("READ_ACCESS_DG3", accessRights);

        // Make a certificate request from a CVCA
        Collection<Certificate> cachain = cvcainfo.getCertificateChain();
        assertEquals(1, cachain.size());
        Certificate cert1 = (Certificate) cachain.iterator().next();
        CardVerifiableCertificate cvcert1 = (CardVerifiableCertificate) cert1;
        assertEquals("SETESTCVCA00001", cvcert1.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated());
        byte[] request = caAdminSession.makeRequest(admin, cvcainfo.getCAId(), cachain, false, false, false, null);
        CVCObject obj = CertificateParser.parseCVCObject(request);
        // We should have created an authenticated request signed by the the old key,
        // but since the CVCA is not renewed, and no old key exists, it will be
        // an un-authenticated request instead.
        CVCertificate reqcert = (CVCertificate)obj;
        assertEquals("SETESTCVCA00001", reqcert.getCertificateBody().getHolderReference().getConcatenated());
        assertEquals("SETESTCVCA00001", reqcert.getCertificateBody().getAuthorityReference().getConcatenated());

        // Make a certificate request from a DV, regenerating keys
        cachain = dvdcainfo.getCertificateChain();
        request = caAdminSession.makeRequest(admin, dvdcainfo.getCAId(), cachain, true, false, true, "foo123");
        obj = CertificateParser.parseCVCObject(request);
        // We should have created an authenticated request signed by the old certificate
        CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest) obj;
        reqcert = authreq.getRequest();
        assertEquals("SETESTDV-D00002", reqcert.getCertificateBody().getHolderReference().getConcatenated());
        // This request is made from the DV targeted for the DV, so the old DV
        // certificate will be the holder ref.
        // Normally you would target an external CA, and thus send in it's
        // cachain. The caRef would be the external CAs holderRef.
        assertEquals("SETESTDV-D00001", reqcert.getCertificateBody().getAuthorityReference().getConcatenated());

        // Get the DVs certificate request signed by the CVCA
        byte[] authrequest = caAdminSession.signRequest(admin, cvcainfo.getCAId(), request, false, false);
        CVCObject parsedObject = CertificateParser.parseCVCObject(authrequest);
        authreq = (CVCAuthenticatedRequest) parsedObject;
        assertEquals("SETESTDV-D00002", authreq.getRequest().getCertificateBody().getHolderReference().getConcatenated());
        assertEquals("SETESTDV-D00001", authreq.getRequest().getCertificateBody().getAuthorityReference().getConcatenated());
        assertEquals("SETESTCVCA00001", authreq.getAuthorityReference().getConcatenated());

        // Get the DVs certificate request signed by the CVCA creating a link
        // certificate.
        // Passing in a request without authrole should return a regular
        // authenticated request though.
        authrequest = caAdminSession.signRequest(admin, cvcainfo.getCAId(), request, false, true);
        parsedObject = CertificateParser.parseCVCObject(authrequest);
        authreq = (CVCAuthenticatedRequest) parsedObject;
        // Pass in a certificate instead
        CardVerifiableCertificate dvdcert = (CardVerifiableCertificate) cachain.iterator().next();
        authrequest = caAdminSession.signRequest(admin, cvcainfo.getCAId(), dvdcert.getEncoded(), false, true);
        parsedObject = CertificateParser.parseCVCObject(authrequest);
        CVCertificate linkcert = (CVCertificate) parsedObject;
        assertEquals("SETESTCVCA00001", linkcert.getCertificateBody().getAuthorityReference().getConcatenated());
        assertEquals("SETESTDV-D00001", linkcert.getCertificateBody().getHolderReference().getConcatenated());

        // Renew again but regenerate keys this time to make sure sequence is
        // updated
        caid = dvdcainfo.getCAId();
        caAdminSession.renewCA(admin, caid, "foo123", true);
        dvdcainfo = caSession.getCAInfo(admin, dvdcaname);
        assertEquals(CAInfo.CATYPE_CVC, dvdcainfo.getCAType());
        cert = (Certificate) dvdcainfo.getCertificateChain().iterator().next();
        assertEquals("CVC", cert.getType());
        assertEquals(CertTools.getSubjectDN(cert), dvddn);
        assertEquals(CertTools.getIssuerDN(cert), rootcadn);
        assertEquals(dvdcainfo.getSubjectDN(), dvddn);
        cvcert = (CardVerifiableCertificate) cert;
        role = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
        assertEquals("DV_D", role);
        String holderRef = cvcert.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated();
        // Sequence must have been updated with 1
        assertEquals("SETESTDV-D00003", holderRef);
    } // test09AddCVCCARSA

    /**
     * 
     * @throws Exception
     */
    @Test
    public void test10AddCVCCAECC() throws Exception {
        removeOldCa("TESTCVCAECC");
        removeOldCa("TESTDVECC-D");
        removeOldCa("TESTDVECC-F");

        boolean ret = false;
        CATokenInfo catokeninfo = new CATokenInfo();
        // catokeninfo.setSignKeySpec("secp256r1");
        catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catokeninfo.setClassPath(SoftCryptoToken.class.getName());
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);

        Properties prop = catokeninfo.getProperties();
        // Set some CA token properties if they are not set already
        if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
            prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf("secp256r1"));
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        }
        catokeninfo.setProperties(prop);

        // No CA Services.
        ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();

        String rootcadn = "CN=TCVCAEC,C=SE";
        String rootcaname = "TESTCVCAECC";
        String dvddn = "CN=TDVEC-D,C=SE";
        String dvdcaname = "TESTDVECC-D";
        String dvfdn = "CN=TDVEC-F,C=FI";
        String dvfcaname = "TESTDVECC-F";

        CAInfo dvdcainfo = null; // to be used for renewal
        CAInfo cvcainfo = null; // to be used for making request

        // Create a root CVCA
        try {
            // adminGroupSession.init(admin, rootcadn.hashCode(), DEFAULT_SUPERADMIN_CN);

            CVCCAInfo cvccainfo = new CVCCAInfo(rootcadn, rootcaname, SecConst.CA_ACTIVE, new Date(), SecConst.CERTPROFILE_FIXED_ROOTCA, 3650, null, // Expiretime
                    CAInfo.CATYPE_CVC, CAInfo.SELFSIGNED, null, catokeninfo, "JUnit CVC CA", -1, null, 24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    10, // Delta CRL period
                    new ArrayList<Integer>(), // CRL publishers
                    true, // Finish User
                    extendedcaservices, new ArrayList<Integer>(), // Approvals Settings
                    1, // Number of Req approvals
                    true, // Include in health check
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true // useCertificateStorage
            );

            caAdminSession.createCA(admin, cvccainfo);

            cvcainfo = caSession.getCAInfo(admin, rootcaname);
            assertEquals(CAInfo.CATYPE_CVC, cvcainfo.getCAType());

            Certificate cert = (Certificate) cvcainfo.getCertificateChain().iterator().next();
            String sigAlg = AlgorithmTools.getSignatureAlgorithm(cert);
            assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, sigAlg);
            assertEquals("CVC", cert.getType());
            assertEquals(rootcadn, CertTools.getSubjectDN(cert));
            assertEquals(rootcadn, CertTools.getIssuerDN(cert));
            assertEquals(rootcadn, cvcainfo.getSubjectDN());
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof ECPublicKey) {
                ECPublicKey epk = (ECPublicKey) pk;
                assertEquals(epk.getAlgorithm(), "ECDSA");
                int len = KeyTools.getKeyLength(epk);
                assertEquals(256, len);
            } else {
                assertTrue("Public key is not ECC", false);
            }
            assertTrue("CA is not valid for the specified duration.",
                    CertTools.getNotAfter(cert).after(new Date(new Date().getTime() + 10 * 364 * 24 * 60 * 60 * 1000L))
                            && CertTools.getNotAfter(cert).before(new Date(new Date().getTime() + 10 * 366 * 24 * 60 * 60 * 1000L)));
            // Check role
            CardVerifiableCertificate cvcert = (CardVerifiableCertificate) cert;
            String role = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
            assertEquals("SETCVCAEC00001", cvcert.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated());
            assertEquals("CVCA", role);
            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }
        assertTrue(ret);

        // Create a Sub DV domestic
        ret = false;
        try {
            // adminGroupSession.init(admin, dvddn.hashCode(), DEFAULT_SUPERADMIN_CN);
            CVCCAInfo cvccainfo = new CVCCAInfo(dvddn, dvdcaname, SecConst.CA_ACTIVE, new Date(), SecConst.CERTPROFILE_FIXED_SUBCA, 3650, null, // Expiretime
                    CAInfo.CATYPE_CVC, rootcadn.hashCode(), null, catokeninfo, "JUnit CVC CA", -1, null, 24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    10, // Delta CRL period
                    new ArrayList<Integer>(), // CRL publishers
                    true, // Finish User
                    extendedcaservices, new ArrayList<Integer>(), // Approvals Settings
                    1, // Number of Req approvals
                    true, // Include in health check
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true // useCertificateStorage
            );

            caAdminSession.createCA(admin, cvccainfo);

            dvdcainfo = caSession.getCAInfo(admin, dvdcaname);
            assertEquals(CAInfo.CATYPE_CVC, dvdcainfo.getCAType());

            Certificate cert = (Certificate) dvdcainfo.getCertificateChain().iterator().next();
            assertEquals("CVC", cert.getType());
            assertEquals(CertTools.getSubjectDN(cert), dvddn);
            assertEquals(CertTools.getIssuerDN(cert), rootcadn);
            assertEquals(dvdcainfo.getSubjectDN(), dvddn);
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof ECPublicKey) {
                ECPublicKey epk = (ECPublicKey) pk;
                assertEquals(epk.getAlgorithm(), "ECDSA");
                int len = KeyTools.getKeyLength(epk);
                assertEquals(0, len); // the DVCA does not include all EC
                // parameters in the public key, so we
                // don't know the key length
            } else {
                assertTrue("Public key is not ECC", false);
            }
            assertTrue("CA is not valid for the specified duration.",
                    CertTools.getNotAfter(cert).after(new Date(new Date().getTime() + 10 * 364 * 24 * 60 * 60 * 1000L))
                            && CertTools.getNotAfter(cert).before(new Date(new Date().getTime() + 10 * 366 * 24 * 60 * 60 * 1000L)));
            // Check role
            CardVerifiableCertificate cvcert = (CardVerifiableCertificate) cert;
            assertEquals("SETDVEC-D00001", cvcert.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated());
            String role = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
            assertEquals("DV_D", role);
            String accessRights = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAccessRight()
                    .name();
            assertEquals("READ_ACCESS_DG3_AND_DG4", accessRights);
            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }
        assertTrue(ret);
        // Create a Sub DV foreign
        ret = false;
        try {
            // adminGroupSession.init(admin, dvfdn.hashCode(), DEFAULT_SUPERADMIN_CN);

            CVCCAInfo cvccainfo = new CVCCAInfo(dvfdn, dvfcaname, SecConst.CA_ACTIVE, new Date(), SecConst.CERTPROFILE_FIXED_SUBCA, 3650, null, // Expiretime
                    CAInfo.CATYPE_CVC, rootcadn.hashCode(), null, catokeninfo, "JUnit CVC CA", -1, null, 24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    10, // Delta CRL period
                    new ArrayList<Integer>(), // CRL publishers
                    true, // Finish User
                    extendedcaservices, new ArrayList<Integer>(), // Approvals Settings
                    1, // Number of Req approvals
                    true, // Include in health check
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true // useCertificateStorage
            );

            caAdminSession.createCA(admin, cvccainfo);

            CAInfo info = caSession.getCAInfo(admin, dvfcaname);
            assertEquals(CAInfo.CATYPE_CVC, info.getCAType());

            Certificate cert = (Certificate) info.getCertificateChain().iterator().next();
            assertEquals("CVC", cert.getType());
            assertEquals(CertTools.getSubjectDN(cert), dvfdn);
            assertEquals(CertTools.getIssuerDN(cert), rootcadn);
            assertEquals(info.getSubjectDN(), dvfdn);
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof ECPublicKey) {
                ECPublicKey epk = (ECPublicKey) pk;
                assertEquals(epk.getAlgorithm(), "ECDSA");
                int len = KeyTools.getKeyLength(epk);
                assertEquals(0, len); // the DVCA does not include all EC
                // parameters in the public key, so we
                // don't know the key length
            } else {
                assertTrue("Public key is not ECC", false);
            }
            assertTrue("CA is not valid for the specified duration.",
                    CertTools.getNotAfter(cert).after(new Date(new Date().getTime() + 10 * 364 * 24 * 60 * 60 * 1000L))
                            && CertTools.getNotAfter(cert).before(new Date(new Date().getTime() + 10 * 366 * 24 * 60 * 60 * 1000L)));
            // Check role
            CardVerifiableCertificate cvcert = (CardVerifiableCertificate) cert;
            assertEquals("FITDVEC-F00001", cvcert.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated());
            String role = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
            assertEquals("DV_F", role);
            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }
        assertTrue("Creating CVC CAs failed", ret);

        // Test to renew a CVC CA
        dvdcainfo = caSession.getCAInfo(admin, dvdcaname);
        Certificate cert = (Certificate) dvdcainfo.getCertificateChain().iterator().next();
        // Verify that fingerprint and CA fingerprint is handled correctly
        CertificateInfo certInfo = certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(cert));
        assertFalse(certInfo.getFingerprint().equals(certInfo.getCAFingerprint()));
        int caid = dvdcainfo.getCAId();
        caAdminSession.renewCA(admin, caid, null, false);
        dvdcainfo = caSession.getCAInfo(admin, dvdcaname);
        assertEquals(CAInfo.CATYPE_CVC, dvdcainfo.getCAType());
        cert = (Certificate) dvdcainfo.getCertificateChain().iterator().next();
        assertEquals("CVC", cert.getType());
        assertEquals(CertTools.getSubjectDN(cert), dvddn);
        assertEquals(CertTools.getIssuerDN(cert), rootcadn);
        assertEquals(dvdcainfo.getSubjectDN(), dvddn);
        // Verify that fingerprint and CA fingerprint is handled correctly
        certInfo = certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(cert));
        assertFalse(certInfo.getFingerprint().equals(certInfo.getCAFingerprint()));
        // It's not possible to check the time for renewal of a CVC CA since the
        // resolution of validity is only days.
        // The only way is to generate a certificate with different access
        // rights in it
        CardVerifiableCertificate cvcert = (CardVerifiableCertificate) cert;
        String role = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
        assertEquals("DV_D", role);
        String accessRights = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAccessRight()
                .name();
        assertEquals("READ_ACCESS_DG3_AND_DG4", accessRights);

        // Make a certificate request from a DV, regenerating keys
        Collection<Certificate> cachain = dvdcainfo.getCertificateChain();
        byte[] request = caAdminSession.makeRequest(admin, dvdcainfo.getCAId(), cachain, true, false, true, "foo123");
        CVCObject obj = CertificateParser.parseCVCObject(request);
        // We should have created an authenticated request signed by the old
        // certificate
        CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest) obj;
        CVCertificate reqcert = authreq.getRequest();
        assertEquals("SETDVEC-D00002", reqcert.getCertificateBody().getHolderReference().getConcatenated());
        // This request is made from the DV targeted for the DV, so the old DV
        // certificate will be the holder ref.
        // Normally you would target an external CA, and thus send in it's
        // cachain. The caRef would be the external CAs holderRef.
        assertEquals("SETDVEC-D00001", reqcert.getCertificateBody().getAuthorityReference().getConcatenated());

        // Get the DVs certificate request signed by the CVCA
        byte[] authrequest = caAdminSession.signRequest(admin, cvcainfo.getCAId(), request, false, false);
        CVCObject parsedObject = CertificateParser.parseCVCObject(authrequest);
        authreq = (CVCAuthenticatedRequest) parsedObject;
        assertEquals("SETDVEC-D00002", authreq.getRequest().getCertificateBody().getHolderReference().getConcatenated());
        assertEquals("SETDVEC-D00001", authreq.getRequest().getCertificateBody().getAuthorityReference().getConcatenated());
        assertEquals("SETCVCAEC00001", authreq.getAuthorityReference().getConcatenated());

        // Get the DVs certificate request signed by the CVCA creating a link
        // certificate.
        // Passing in a request without authrole should return a regular
        // authenticated request though.
        authrequest = caAdminSession.signRequest(admin, cvcainfo.getCAId(), request, false, true);
        parsedObject = CertificateParser.parseCVCObject(authrequest);
        authreq = (CVCAuthenticatedRequest) parsedObject;
        // Pass in a certificate instead
        CardVerifiableCertificate dvdcert = (CardVerifiableCertificate) cachain.iterator().next();
        authrequest = caAdminSession.signRequest(admin, cvcainfo.getCAId(), dvdcert.getEncoded(), false, true);
        parsedObject = CertificateParser.parseCVCObject(authrequest);
        CVCertificate linkcert = (CVCertificate) parsedObject;
        assertEquals("SETCVCAEC00001", linkcert.getCertificateBody().getAuthorityReference().getConcatenated());
        assertEquals("SETDVEC-D00001", linkcert.getCertificateBody().getHolderReference().getConcatenated());

        // Renew again but regenerate keys this time to make sure sequence is
        // updated
        caid = dvdcainfo.getCAId();
        caAdminSession.renewCA(admin, caid, "foo123", true);
        dvdcainfo = caSession.getCAInfo(admin, dvdcaname);
        assertEquals(CAInfo.CATYPE_CVC, dvdcainfo.getCAType());
        cert = (Certificate) dvdcainfo.getCertificateChain().iterator().next();
        assertEquals("CVC", cert.getType());
        assertEquals(CertTools.getSubjectDN(cert), dvddn);
        assertEquals(CertTools.getIssuerDN(cert), rootcadn);
        assertEquals(dvdcainfo.getSubjectDN(), dvddn);
        cvcert = (CardVerifiableCertificate) cert;
        role = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
        assertEquals("DV_D", role);
        String holderRef = cvcert.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated();
        // Sequence must have been updated with 1
        assertEquals("SETDVEC-D00003", holderRef);

        // Make a certificate request from a CVCA
        cachain = cvcainfo.getCertificateChain();
        assertEquals(1, cachain.size());
        Certificate cert1 = (Certificate) cachain.iterator().next();
        CardVerifiableCertificate cvcert1 = (CardVerifiableCertificate) cert1;
        assertEquals("SETCVCAEC00001", cvcert1.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated());
        request = caAdminSession.makeRequest(admin, cvcainfo.getCAId(), cachain, false, false, false, null);
        obj = CertificateParser.parseCVCObject(request);
        // We should have created an un-authenticated request, because there
        // does not exist any old key
        CVCertificate cvcertreq = (CVCertificate) obj;
        assertEquals("SETCVCAEC00001", cvcertreq.getCertificateBody().getHolderReference().getConcatenated());
        assertEquals("SETCVCAEC00001", cvcertreq.getCertificateBody().getAuthorityReference().getConcatenated());

        // Renew the CVCA, generating new keys
        caAdminSession.renewCA(admin, cvcainfo.getCAId(), "foo123", true);

        // Make a certificate request from a CVCA again
        cvcainfo = caSession.getCAInfo(admin, rootcaname);
        cachain = cvcainfo.getCertificateChain();
        assertEquals(1, cachain.size());
        Certificate cert2 = (Certificate) cachain.iterator().next();
        CardVerifiableCertificate cvcert2 = (CardVerifiableCertificate) cert2;
        assertEquals("SETCVCAEC00002", cvcert2.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated());
        request = caAdminSession.makeRequest(admin, cvcainfo.getCAId(), cachain, false, false, false, null);
        obj = CertificateParser.parseCVCObject(request);
        // We should have created an authenticated request signed by the old
        // certificate
        CVCAuthenticatedRequest authreq1 = (CVCAuthenticatedRequest) obj;
        CVCertificate reqcert1 = authreq1.getRequest();
        assertEquals("SETCVCAEC00002", reqcert1.getCertificateBody().getHolderReference().getConcatenated());
        assertEquals("SETCVCAEC00002", reqcert1.getCertificateBody().getAuthorityReference().getConcatenated());
    } // test10AddCVCCAECC

    /**
     * Test that we can create a SubCA signed by an external RootCA. The SubCA create a certificate request sent to the RootCA that creates a
     * certificate which is then received on the SubCA again.
     * 
     * @throws Exception
     */
    @Test
    public void test11RSASignedByExternal() throws Exception {
        removeOldCa("TESTSIGNEDBYEXTERNAL");

        boolean ret = false;
        CAInfo info = null;
        try {
            // adminGroupSession.init(admin, "CN=TESTSIGNEDBYEXTERNAL".hashCode(), DEFAULT_SUPERADMIN_CN);

            CATokenInfo catokeninfo = new CATokenInfo();
            catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
            catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
            catokeninfo.setClassPath(SoftCryptoToken.class.getName());
            catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            Properties prop = catokeninfo.getProperties();
            // Set some CA token properties if they are not set already
            if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
                prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf("1024"));
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
            }
            catokeninfo.setProperties(prop);

            // Create and active OSCP CA Service.
            ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, " + "CN=TESTSIGNEDBYEXTERNAL",
                    "", "1024", AlgorithmConstants.KEYALGORITHM_RSA));
            extendedcaservices.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=CMSCertificate, " + "CN=TESTSIGNEDBYEXTERNAL", "",
                    "1024", AlgorithmConstants.KEYALGORITHM_RSA));

            X509CAInfo cainfo = new X509CAInfo("CN=TESTSIGNEDBYEXTERNAL", "TESTSIGNEDBYEXTERNAL", SecConst.CA_ACTIVE, new Date(), "",
                    SecConst.CERTPROFILE_FIXED_SUBCA, 1000, null, // Expiretime
                    CAInfo.CATYPE_X509, CAInfo.SIGNEDBYEXTERNALCA, // Signed by the first TEST CA we created
                    (Collection<Certificate>) null, catokeninfo, "JUnit RSA CA Signed by external", -1, null, null, // PolicyId
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
                    null // cmpRaAuthSecret
            );

            try {
                caSession.getCAInfo(admin, "TESTSIGNEDBYEXTERNAL");
                fail("External CA exists in database. Test can't continue.");
            } catch (CADoesntExistsException e) {
                // Life is awesome
            }
            caAdminSession.createCA(admin, cainfo);

            info = caSession.getCAInfo(admin, "TESTSIGNEDBYEXTERNAL");
            assertEquals(SecConst.CA_WAITING_CERTIFICATE_RESPONSE, info.getStatus());

            // Generate a certificate request from the CA and send to the TEST CA
            CAInfo rootinfo = caSession.getCAInfo(caAdmin, getTestCAName());
            Collection<Certificate> rootcacertchain = rootinfo.getCertificateChain();
            byte[] request = caAdminSession.makeRequest(admin, info.getCAId(), rootcacertchain, false, false, false, null);
            info = caSession.getCAInfo(admin, "TESTSIGNEDBYEXTERNAL");
            assertEquals(SecConst.CA_WAITING_CERTIFICATE_RESPONSE, info.getStatus());
            PKCS10RequestMessage msg = new PKCS10RequestMessage(request);
            assertEquals("CN=TESTSIGNEDBYEXTERNAL", msg.getRequestDN());

            // Receive the certificate request on the TEST CA
            info.setSignedBy("CN=TEST".hashCode());
            ResponseMessage resp = caAdminSession.processRequest(admin, info, msg);

            // Receive the signed certificate back on our SubCA
            caAdminSession.receiveResponse(admin, info.getCAId(), resp, null, null);

            // Check that the CA has the correct certificate chain now
            info = caSession.getCAInfo(admin, "TESTSIGNEDBYEXTERNAL");
            assertEquals(SecConst.CA_ACTIVE, info.getStatus());
            Iterator<Certificate> iter = info.getCertificateChain().iterator();
            Certificate cert = iter.next();
            String sigAlg = AlgorithmTools.getSignatureAlgorithm(cert);
            assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, sigAlg);
            assertTrue("Error in created ca certificate", CertTools.getSubjectDN(cert).equals("CN=TESTSIGNEDBYEXTERNAL"));
            assertTrue("Error in created ca certificate", CertTools.getIssuerDN(cert).equals("CN=TEST"));
            assertTrue("Creating CA failed", info.getSubjectDN().equals("CN=TESTSIGNEDBYEXTERNAL"));
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof RSAPublicKey) {
                RSAPublicKey rsapk = (RSAPublicKey) pk;
                assertEquals(rsapk.getAlgorithm(), "RSA");
            } else {
                assertTrue("Public key is not EC", false);
            }
            cert = (X509Certificate) iter.next();
            assertTrue("Error in root ca certificate", CertTools.getSubjectDN(cert).equals("CN=TEST"));
            assertTrue("Error in root ca certificate", CertTools.getIssuerDN(cert).equals("CN=TEST"));

            ret = true;

        } catch (CAExistsException pee) {
            log.info("CA exists: ", pee);
        }

        // Make a certificate request from the CA
        Collection<Certificate> cachain = info.getCertificateChain();
        byte[] request = caAdminSession.makeRequest(admin, info.getCAId(), cachain, false, false, false, null);
        info = caSession.getCAInfo(admin, "TESTSIGNEDBYEXTERNAL");
        assertEquals(SecConst.CA_ACTIVE, info.getStatus()); // No new keys
        // generated, still
        // active
        PKCS10RequestMessage msg = new PKCS10RequestMessage(request);
        assertEquals("CN=TESTSIGNEDBYEXTERNAL", msg.getRequestDN());

        assertTrue("Creating RSA CA (signed by external) failed", ret);
    } // test10RSASignedByExternal

    /**
     * adds a CA using DSA keys to the database.
     * 
     * It also checks that the CA is stored correctly.
     * 
     * @throws Exception error
     */
    @Test
    public void test12AddDSACA() throws Exception {
        boolean ret = false;
        try {
            removeTestCA("TESTDSA"); // We cant be sure this CA was not left
            // over from some other failed test
            // adminGroupSession.init(admin, getTestCAId(), DEFAULT_SUPERADMIN_CN);
            CATokenInfo catokeninfo = new CATokenInfo();
            catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
            catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
            catokeninfo.setClassPath(SoftCryptoToken.class.getName());
            catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_DSA);
            catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);

            Properties prop = catokeninfo.getProperties();
            // Set some CA token properties if they are not set already
            if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
                prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf("1024"));
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
                prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
            }
            catokeninfo.setProperties(prop);

            // Create and active OSCP CA Service.
            ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, " + "CN=TESTDSA", "", "1024",
                    AlgorithmConstants.KEYALGORITHM_DSA));

            X509CAInfo cainfo = new X509CAInfo("CN=TESTDSA", "TESTDSA", SecConst.CA_ACTIVE, new Date(), "", SecConst.CERTPROFILE_FIXED_ROOTCA, 3650,
                    null, // Expiretime
                    CAInfo.CATYPE_X509, CAInfo.SELFSIGNED, (Collection<Certificate>) null, catokeninfo, "JUnit DSA CA", -1, null, null, // PolicyId
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
                    null // cmpRaAuthSecret
            );

            caAdminSession.createCA(admin, cainfo);

            CAInfo info = caSession.getCAInfo(admin, "TESTDSA");

            Collection<Certificate> rootcacertchain = info.getCertificateChain();
            X509Certificate cert = (X509Certificate) rootcacertchain.iterator().next();
            String sigAlg = AlgorithmTools.getSignatureAlgorithm(cert);
            assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_DSA, sigAlg);
            assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals("CN=TESTDSA"));
            assertTrue("Creating CA failed", info.getSubjectDN().equals("CN=TESTDSA"));
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof DSAPublicKey) {
                DSAPublicKey rsapk = (DSAPublicKey) pk;
                assertEquals(rsapk.getAlgorithm(), "DSA");
            } else {
                assertTrue("Public key is not DSA", false);
            }
            assertTrue(
                    "CA is not valid for the specified duration.",
                    cert.getNotAfter().after(new Date(new Date().getTime() + 10 * 364 * 24 * 60 * 60 * 1000L))
                            && cert.getNotAfter().before(new Date(new Date().getTime() + 10 * 366 * 24 * 60 * 60 * 1000L)));
            ret = true;

            // Test to generate a certificate request from the CA
            Collection<Certificate> cachain = info.getCertificateChain();
            byte[] request = caAdminSession.makeRequest(admin, info.getCAId(), cachain, false, false, false, null);
            PKCS10RequestMessage msg = new PKCS10RequestMessage(request);
            assertEquals("CN=TESTDSA", msg.getRequestDN());
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }

        assertTrue("Creating DSA CA failed", ret);
    } // test12AddDSACA

    @Test
    public void test13RenewCA() throws Exception {
        // Test renew cacert
        CAInfo info = caSession.getCAInfo(admin, getTestCAId());
        Collection<Certificate> certs = info.getCertificateChain();
        X509Certificate cacert1 = (X509Certificate) certs.iterator().next();
        caAdminSession.renewCA(admin, getTestCAId(), "foo123", false);
        info = caSession.getCAInfo(admin, getTestCAId());
        certs = info.getCertificateChain();
        X509Certificate cacert2 = (X509Certificate) certs.iterator().next();
        assertFalse(cacert1.getSerialNumber().equals(cacert2.getSerialNumber()));
        assertEquals(new String(CertTools.getSubjectKeyId(cacert1)), new String(CertTools.getSubjectKeyId(cacert2)));
        cacert2.verify(cacert1.getPublicKey()); // throws if it fails

        // Test renew CA keys
        caAdminSession.renewCA(admin, getTestCAId(), "foo123", true);
        info = caSession.getCAInfo(admin, getTestCAId());
        certs = info.getCertificateChain();
        X509Certificate cacert3 = (X509Certificate) certs.iterator().next();
        assertFalse(cacert2.getSerialNumber().equals(cacert3.getSerialNumber()));
        String keyid1 = new String(CertTools.getSubjectKeyId(cacert2));
        String keyid2 = new String(CertTools.getSubjectKeyId(cacert3));
        assertFalse(keyid1.equals(keyid2));

        // Test create X.509 link certificate (NewWithOld rollover cert)
        // We have cacert3 that we want to sign with the old keys from cacert2,
        // create a link certificate.
        // That link certificate should have the same subjetcKeyId as cert3, but
        // be possible to verify with cert2.
        byte[] bytes = caAdminSession.signRequest(admin, getTestCAId(), cacert3.getEncoded(), true, true);
        X509Certificate cacert4 = (X509Certificate) CertTools.getCertfromByteArray(bytes);
        // Same public key as in cacert3 -> same subject key id
        keyid1 = new String(CertTools.getSubjectKeyId(cacert3));
        keyid2 = new String(CertTools.getSubjectKeyId(cacert4));
        assertTrue(keyid1.equals(keyid2));
        // Same signer as for cacert2 -> same auth key id in cacert4 as subject
        // key id in cacert2
        keyid1 = new String(CertTools.getSubjectKeyId(cacert2));
        keyid2 = new String(CertTools.getAuthorityKeyId(cacert4));
        assertTrue(keyid1.equals(keyid2));
        cacert4.verify(cacert2.getPublicKey());

        // Test make request just making a request using the old keys
        byte[] request = caAdminSession.makeRequest(admin, getTestCAId(), new ArrayList<Certificate>(), false, false, false, "foo123");
        assertNotNull(request);
        PKCS10RequestMessage msg = RequestMessageUtils.genPKCS10RequestMessage(request);
        PublicKey pk1 = cacert3.getPublicKey();
        PublicKey pk2 = msg.getRequestPublicKey();
        String key1 = new String(Base64.encode(pk1.getEncoded()));
        String key2 = new String(Base64.encode(pk2.getEncoded()));
        // A plain request using the CAs key will have the same public key
        assertEquals(key1, key2);
        // Test make request generating new keys
        request = caAdminSession.makeRequest(admin, getTestCAId(), new ArrayList<Certificate>(), true, false, true, "foo123");
        assertNotNull(request);
        msg = RequestMessageUtils.genPKCS10RequestMessage(request);
        pk1 = cacert3.getPublicKey();
        pk2 = msg.getRequestPublicKey();
        key1 = new String(Base64.encode(pk1.getEncoded()));
        key2 = new String(Base64.encode(pk2.getEncoded()));
        // A plain request using new CAs key can not have the same keys
        assertFalse(key1.equals(key2));
        // After this (new keys activated but no cert response received) status
        // should be waiting...
        info = caSession.getCAInfo(admin, getTestCAId());
        assertEquals(SecConst.CA_WAITING_CERTIFICATE_RESPONSE, info.getStatus());

        // To clean up after us so the active key is not out of sync with the
        // active certificate, we should simply renew the CA
        info.setStatus(SecConst.CA_ACTIVE);
        caAdminSession.editCA(admin, info); // need active status in order
        // to do renew
        caAdminSession.renewCA(admin, getTestCAId(), "foo123", false);
    } // test13RenewCA

    @Test
    public void test14RevokeCA() throws Exception {
        final String caname = "TestRevokeCA";
        removeTestCA(caname);
        createTestCA(caname);
        try {
            CAInfo info = caSession.getCAInfo(admin, caname);
            assertEquals(SecConst.CA_ACTIVE, info.getStatus());
            assertEquals(RevokedCertInfo.NOT_REVOKED, info.getRevocationReason());
            assertNull(info.getRevocationDate());

            // Revoke the CA
            caAdminSession.revokeCA(admin, info.getCAId(), RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE);
            info = caSession.getCAInfo(admin, caname);
            assertEquals(SecConst.CA_REVOKED, info.getStatus());
            assertEquals(RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, info.getRevocationReason());
            assertTrue(info.getRevocationDate().getTime() > 0);
        } finally {
            removeTestCA(caname);
        }
    } // test14RevokeCA

    @Test
    public void test15ExternalExpiredCA() throws Exception {
        final String caname = "TestExternalExpiredCA";
        byte[] testcert = Base64.decode(("MIICDjCCAXegAwIBAgIIaXCEunuPDowwDQYJKoZIhvcNAQEFBQAwFzEVMBMGA1UE"
                + "AwwMc2hvcnQgZXhwaXJlMB4XDTExMDIwNTE3MjI1MloXDTExMDIwNTE4MjIxM1ow"
                + "FzEVMBMGA1UEAwwMc2hvcnQgZXhwaXJlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB"
                + "iQKBgQCNAygw3H9WuThxxFAv2oc5SzijHLUdvgD+Y9E3nKWWgRq1ECcKo0d60U24"
                + "gJiuSkH+PcC300a1AnfWAac/MkuFS9F58J6vjud+AA0MzoD5Tlc9lbxQy6qoKF29"
                + "87VMITZjISSdfnlfWbXVeNqTrqeTBreOS34TTZ7bLzBCvGcq1wIDAQABo2MwYTAd"
                + "BgNVHQ4EFgQUfLHTt9G8cdsVxZR9gOsHUqqh/1wwDwYDVR0TAQH/BAUwAwEB/zAf"
                + "BgNVHSMEGDAWgBR8sdO30bxx2xXFlH2A6wdSqqH/XDAOBgNVHQ8BAf8EBAMCAYYw"
                + "DQYJKoZIhvcNAQEFBQADgYEAS4PvelI9Fmxxcbs0Nrx8qk+TlREOeDX+rsXvKcJ2"
                + "gGEhtMX1yCNn0uSQuc/mM4Dz5faxCCQQMZl8Vp07d1MrTMYcka+P6RtEKneXfLim"
                + "fXnqR22xd2P7ssXE52/tTnAyJbYUrOOCI6iiek3dZN8oTmGhZUBHIgFzxC/8MgHa" + "G6Y=").getBytes());
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        removeOldCa(caname); // for the test
        List<Certificate> certs = new ArrayList<Certificate>();
        certs.add(cert);

        try {
            // Import the CA certificate
            caAdminSession.importCACertificate(admin, caname, certs);
            CAInfo info = caSession.getCAInfo(admin, caname);
            // The CA must not get stats SecConst.CA_EXPIRED when it is an external CA
            assertEquals(SecConst.CA_EXTERNAL, info.getStatus());
        } finally {
            removeOldCa(caname); // for the test
        }
    } // test15ExternalExpiredCA

    /** Try to create a CA using invalid parameters */
    @Test
    public void test16InvalidCreateCaActions() throws Exception {
        log.trace(">test16InvalidCreateCaActions()");
        removeTestCA("TESTFAIL"); // We cant be sure this CA was not left over from
        // some other failed test
        // adminGroupSession.init(admin, getTestCAId(), DEFAULT_SUPERADMIN_CN);
        CATokenInfo catokeninfo = new CATokenInfo();
        catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catokeninfo.setClassPath(SoftCryptoToken.class.getName());
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);

        Properties prop = catokeninfo.getProperties();
        // Set some CA token properties if they are not set already
        if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
            prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf("1024"));
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        }
        catokeninfo.setProperties(prop);

        // Create and active OSCP CA Service.
        ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, " + "CN=TEST", "", "1024",
                AlgorithmConstants.KEYALGORITHM_RSA));

        X509CAInfo cainfo = new X509CAInfo("CN=TESTFAIL", "TESTFAIL", SecConst.CA_ACTIVE, new Date(), "", SecConst.CERTPROFILE_FIXED_ROOTCA, 3650,
                null, // Expiretime
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
                null // cmpRaAuthSecret
        );

        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new X500Principal("C=SE,O=UnlovedUser,CN=UnlovedUser"));
        AuthenticationToken unpriviledgedUser = simpleAuthenticationProvider.authenticate(new AuthenticationSubject(principals, null));
        // Try to create the CA as an unprivileged user
        try {
            caAdminSession.createCA(unpriviledgedUser, cainfo);
            assertTrue("Was able to create CA as unprivileged user.", false);
        } catch (AuthorizationDeniedException e) {
            // Expected
        }
        // Try to create the CA with a 0 >= CA Id < CAInfo.SPECIALCAIDBORDER
        setPrivateFieldInSuper(cainfo, "caid", CAInfo.SPECIALCAIDBORDER - 1);
        try {
            caAdminSession.createCA(admin, cainfo);
            assertTrue("Was able to create CA with reserved CA Id.", false);
        } catch (CAExistsException e) {
            // Expected
        }
        // Try to create a CA where the CA Id already exists (but not the name)
        CAInfo caInfoTest = caSession.getCAInfo(admin, getTestCAName());
        setPrivateFieldInSuper(cainfo, "caid", caInfoTest.getCAId());
        try {
            caAdminSession.createCA(admin, cainfo);
            assertTrue("Was able to create CA with CA Id of already existing CA.", false);
        } catch (CAExistsException e) {
            // Expected
        }
        log.trace("<test16InvalidCreateCaActions()");
    }

    @Test
    public void test17InvalidEditCaActions() throws Exception {
        log.trace(">test17InvalidEditCaActions()");
        CAInfo caInfoTest = caSession.getCAInfo(admin, getTestCAName());
        // Try to edit the CA as an unprivileged user

        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new X500Principal("C=SE,O=UnlovedUser,CN=UnlovedUser"));
        AuthenticationToken unpriviledgedUser = simpleAuthenticationProvider.authenticate(new AuthenticationSubject(principals, null));

        try {
            caAdminSession.editCA(unpriviledgedUser, caInfoTest);
            assertTrue("Was able to edit CA as unprivileged user.", false);
        } catch (AuthorizationDeniedException e) {
            // Expected
        }
        // Try to edit the CA with 'null' authentication code
        CATokenInfo caTokenInfoTest = caInfoTest.getCATokenInfo();
        caTokenInfoTest.setAuthenticationCode(null);
        caInfoTest.setCATokenInfo(caTokenInfoTest);
        try {
            caAdminSession.editCA(unpriviledgedUser, caInfoTest);
            assertTrue("Was able to edit CA with null authentication code.", false);
        } catch (AuthorizationDeniedException e) {
            // Expected
        }
        // Try to edit the CA with wrong authentication code
        caInfoTest.getCATokenInfo().setAuthenticationCode("wrong code");
        caInfoTest.setCATokenInfo(caTokenInfoTest);
        try {
            caAdminSession.editCA(unpriviledgedUser, caInfoTest);
            assertTrue("Was able to edit CA with null authentication code.", false);
        } catch (AuthorizationDeniedException e) {
            // Expected
        }
        log.trace("<test17InvalidEditCaActions()");
    }

    /** Get CA Info using an unprivileged admin and then trying by pretending to be privileged. */
    @Test
    public void test18PublicWebCaInfoFetch() throws Exception {
        log.trace(">test18PublicWebCaInfoFetch()");

        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new X500Principal("C=SE,O=UnlovedUser,CN=UnlovedUser"));
        AuthenticationToken unpriviledgedUser = simpleAuthenticationProvider.authenticate(new AuthenticationSubject(principals, null));

        // Try to get CAInfo as an unprivileged user using remote EJB
        try {
            caSession.getCAInfo(unpriviledgedUser, getTestCAName());
            fail("Was able to get CA info from remote EJB/CLI pretending to be an unpriviledged user");
        } catch (AuthorizationDeniedException ignored) {
            // OK
        }
        try {
            caSession.getCAInfo(unpriviledgedUser, "CN=TEST".hashCode());
            fail("Was able to get CA info from remote EJB/CLI pretending to be an unpriviledged user");
        } catch (AuthorizationDeniedException ignored) {
            // OK
        }

        // FIXME: How do the following tests apply in the future?

        // Try to get CAInfo pretending to be an privileged user using remote EJB
        try {
            CAInfo info = caSession.getCAInfo(admin, getTestCAName());
            System.out.println("info: " + info);
            fail("Was able to get CA info from remote EJB/CLI pretending to be INTERNALUSER");
        } catch (CADoesntExistsException ignored) {
            // OK
        }
        try {
            caSession.getCAInfo(admin, "CN=TEST".hashCode());
            fail("Was able to get CA info from remote EJB/CLI pretending to be INTERNALUSER");
        } catch (CADoesntExistsException ignored) {
            // OK
        }
        log.trace("<test18PublicWebCaInfoFetch()");
    }

    @Test
    public void test19UnprivilegedCaMakeRequest() throws Exception {
        log.trace(">test19UnprivilegedCaMakeRequest()");

        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new X500Principal("C=SE,O=UnlovedUser,CN=UnlovedUser"));
        AuthenticationToken unpriviledgedUser = simpleAuthenticationProvider.authenticate(new AuthenticationSubject(principals, null));

        try {
            caAdminSession.makeRequest(unpriviledgedUser, 0, null, false, false, false, null);
            assertTrue("Was able to make request to CA as unprivileged user.", false);
        } catch (AuthorizationDeniedException e) {
            // Expected
        }
        log.trace("<test19UnprivilegedCaMakeRequest()");
    }

    @Test
    public void test20BadCaReceiveResponse() throws Exception {
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new X500Principal("C=SE,O=UnlovedUser,CN=UnlovedUser"));
        AuthenticationToken unpriviledgedUser = simpleAuthenticationProvider.authenticate(new AuthenticationSubject(principals, null));

        log.trace(">test20BadCaReceiveResponse()");
        try {
            caAdminSession.receiveResponse(unpriviledgedUser, 0, null, null, null);
            fail("Was able to receiveResponse for a CA as unprivileged user.");
        } catch (AuthorizationDeniedException e) {
            // Expected
        }
        try {
            caAdminSession.receiveResponse(admin, -1, null, null, null);
            fail("Was able to receiveResponse for a CA that does not exist.");
        } catch (CADoesntExistsException e) {
            // Expected
        }
        try {
            caAdminSession.receiveResponse(admin, "CN=TEST".hashCode(), new CmpResponseMessage(), null, null);
            fail("Was able to receiveResponse for a CA with a non X509ResponseMessage.");
        } catch (EjbcaException e) {
            // Expected
        }
        try {
            ResponseMessage resp = new X509ResponseMessage();
            resp.setCertificate(caSession.getCAInfo(admin, getTestCAName()).getCertificateChain().iterator().next());
            caAdminSession.receiveResponse(admin, "CN=TEST".hashCode(), resp, null, null);
            fail("Was able to receiveResponse for a CA that is not 'signed by external'.");
        } catch (EjbcaException e) {
            // Expected
        }
        log.trace("<test20BadCaReceiveResponse()");
    }

    @Test
    public void test21UnprivilegedCaProcessRequest() throws Exception {
        log.trace(">test21UnprivilegedCaProcessRequest()");
        CAInfo caInfo = caSession.getCAInfo(admin, getTestCAName());
        try {
            // Try to process a request for a CA with an unprivileged user.
            caAdminSession.processRequest(roleMgmgToken, caInfo, null);
            fail("Was able to process request to CA as unprivileged user.");
        } catch (AuthorizationDeniedException e) {
            // Expected
        }
        // Try to process a request for a CA with a 0 >= CA Id < CAInfo.SPECIALCAIDBORDER
        setPrivateFieldInSuper(caInfo, "caid", CAInfo.SPECIALCAIDBORDER - 1);
        try {
            caAdminSession.processRequest(admin, caInfo, null);
            fail("Was able to create CA with reserved CA Id.");
        } catch (CAExistsException e) {
            // Expected
        }
        log.trace("<test21UnprivilegedCaProcessRequest()");
    }

    /**
     * Preemtively remove CA in case it was created by a previous run:
     * 
     * @throws AuthorizationDeniedException
     */
    private void removeOldCa(String caName) throws AuthorizationDeniedException {
        HashMap<Integer, String> nameMap = caAdminSession.getCAIdToNameMap(admin);
        if (nameMap.containsValue(caName)) {
            for (Entry<Integer, String> entry : nameMap.entrySet()) {
                if (entry.getValue().equals(caName)) {
                    caSession.removeCA(admin, entry.getKey());
                    break;
                }
            }

        }
    }

    /** Used for direct manipulation of objects without setters. */
    private void setPrivateFieldInSuper(Object object, String fieldName, Object value) {
        log.trace(">setPrivateField");
        try {
            Field field = object.getClass().getSuperclass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(object, value);
        } catch (Exception e) {
            log.error("", e);
            assertTrue("Could not set " + fieldName + " to " + value + ": " + e.getMessage(), false);
        }
        log.trace("<setPrivateField");
    }

}