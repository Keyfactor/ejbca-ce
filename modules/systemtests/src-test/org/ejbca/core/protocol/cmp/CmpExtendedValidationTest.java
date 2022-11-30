/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.TestRaMasterApiProxySessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests that "Extended Validation" works and is performed on the RA side,
 * before the requests reach the CA.
 */
public class CmpExtendedValidationTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CmpExtendedValidationTest.class);

    private static final String ISSUER_CA_NAME = "CmpExternalValidationTestCA";
    private static final String ISSUER_CA_1_NAME = "CmpExternalValidationTestCA1";
    private static final String ISSUER_CA_2_NAME = "CmpExternalValidationTestCA2";
    private static final String ISSUER_DN = "O=CmpTests,OU=FoooUåäö,CN=" + ISSUER_CA_NAME + "";
    private static final String ISSUER_1_DN = "O=CmpTests,OU=FoooUåäö,CN=" + ISSUER_CA_1_NAME + "";
    private static final String ISSUER_2_DN = "O=CmpTests,OU=FoooUåäö,CN=" + ISSUER_CA_2_NAME + "";
    private static final int KEYUSAGE = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
    private static final String ALIAS = "CmpExtendedValidationTest";
    private static final String TEST_ROLE = "CmpExtendedValidationTest";
    private static final String PBEPASSWORD = "pbe123";
    private static final String SIGNINGCERT_EE = "CmpExtendedValidationTest_signingcertuser";
    private static final String SIGNINGCERT_DN = "O=CmpExtendedValidationTest,CN=signingcert";
    private static final String CLIENT_MODE_ENDENTITY = "cmp_externalvalidation_test";

    private static final X509CA testx509ca;
    private static final X509Certificate cacert;
    private static final String cafp;
    private static final KeyPair keys;
    private static final PrivateKey caPrivateKey;

    static { // runs only once for all test cases
        try {
            CaTestUtils.removeCa(ADMIN, ISSUER_CA_NAME, ISSUER_CA_NAME);
            CaTestUtils.removeCa(ADMIN, ISSUER_CA_1_NAME, ISSUER_CA_1_NAME);
            CaTestUtils.removeCa(ADMIN, ISSUER_CA_2_NAME, ISSUER_CA_2_NAME);
            testx509ca = CaTestUtils.createTestX509CA(ISSUER_DN, null, false, KEYUSAGE);
            cacert = (X509Certificate) testx509ca.getCACertificate();
            cafp = CertTools.getFingerprintAsString(cacert);
            caPrivateKey = CaTestUtils.getCaPrivateKey(testx509ca);
            keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create test CA and keys.", e);
        }
    }

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private final TestRaMasterApiProxySessionRemote testRaMasterApiProxyBean = EjbRemoteHelper.INSTANCE
            .getRemoteSession(TestRaMasterApiProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final CmpConfiguration cmpConfiguration;

    // From current request
    private X500Name userDnX500;
    private byte[] nonce;
    private byte[] transid;
    private int reqId;


    public CmpExtendedValidationTest() {
        super();
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        caSession.addCA(ADMIN, testx509ca);
        final CAInfo cainfo = testx509ca.getCAInfo();
        cainfo.setDoEnforceUniquePublicKeys(false);
        caSession.editCA(ADMIN, cainfo);

        cmpConfiguration.addAlias(ALIAS);
        cmpConfiguration.setRAMode(ALIAS, true);
        cmpConfiguration.setAllowRAVerifyPOPO(ALIAS, true);
        cmpConfiguration.setResponseProtection(ALIAS, "pbe");
        cmpConfiguration.setRACertProfile(ALIAS, CP_DN_OVERRIDE_NAME);
        cmpConfiguration.setRAEEProfile(ALIAS, String.valueOf(eepDnOverrideId));
        cmpConfiguration.setRACAName(ALIAS, testx509ca.getName());
        cmpConfiguration.setExtractUsernameComponent(ALIAS, "CN");
        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(ALIAS, PBEPASSWORD);
        cmpConfiguration.setUseExtendedValidation(ALIAS, true);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
        clearCmpCaches();

        testRaMasterApiProxyBean.enableFunctionTracingForTest();
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        clearCmpCaches();
        testRaMasterApiProxyBean.restoreFunctionTracingAfterTest();
        caSession.removeCA(ADMIN, testx509ca.getCAId());
        cmpConfiguration.removeAlias(ALIAS);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
        roleSession.deleteRoleIdempotent(ADMIN, null, TEST_ROLE);
        internalCertificateStoreSession.removeCertificatesByIssuer(CertTools.stringToBCDNString(ISSUER_DN));
        internalCertificateStoreSession.removeCertificatesByIssuer(CertTools.stringToBCDNString(ISSUER_1_DN));
        internalCertificateStoreSession.removeCertificatesByIssuer(CertTools.stringToBCDNString(ISSUER_2_DN));
        internalCertificateStoreSession.removeCertificatesByUsername(CLIENT_MODE_ENDENTITY);
        if (endEntityManagementSession.existsUser(CLIENT_MODE_ENDENTITY)) {
            endEntityManagementSession.deleteUser(ADMIN, CLIENT_MODE_ENDENTITY);
        }
    }

    @Override
    public String getRoleName() {
        return "CmpExtendedValidationTest";
    }

    /**
     * This test will verify that unsigned messages are rejected if signature is required.
     */
    @Test
    public void testUnSignedMessageRejected() throws Exception {
        log.trace(">testUnSignedMessageRejected");
        final PKIMessage req = genCertReq("C=SE,O=PrimeKey,CN=testVerifyUnSignedMessageRejected");
        // Send CMP request
        final byte[] resp = sendCmpHttp(req.getEncoded(), 200, ALIAS);
        checkCmpFailMessage(resp, "Authentication failed for message. Signature/HMAC verification was required by CMP RA, but not found in message.", PKIBody.TYPE_ERROR, 0, PKIFailureInfo.badRequest);
        shouldBeRejected();
        log.trace("<testUnSignedMessageRejected");
    }

    /**
     * This test will verify that a signed message not containing the signing certificate as payload is rejected.
     */
    @Test
    public void testRejectMissingExtraCert() throws Exception {
        log.trace(">testRejectMissingExtraCert");
        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(ALIAS, testx509ca.getName());
        cmpConfiguration.setResponseProtection(ALIAS, "signature");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);

        final PKIMessage req = genCertReq("C=SE,O=PrimeKey,CN=testRejectMissingExtraCert");

        final ArrayList<Certificate> signCertColl = new ArrayList<>();
        final byte[] messageBytes = CmpMessageHelper.signPKIMessage(req, signCertColl, keys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1,
                BouncyCastleProvider.PROVIDER_NAME);
        // Send CMP request
        final byte[] resp = sendCmpHttp(messageBytes, 200, ALIAS);
        checkCmpFailMessage(resp, "Authentication failed for message. ExtraCerts field was blank, could not verify signature..", PKIBody.TYPE_ERROR, 0, PKIFailureInfo.badRequest);
        shouldBeRejected();
        log.trace("<testRejectMissingExtraCert");
    }

    /**
     * This test will verify that a message containing a signature without extraCerts is rejected also when HMAC is configured.
     */
    @Test
    public void testRejectMissingExtraCertButExpectingHmac() throws Exception {
        log.trace(">testRejectSignedButExpectingHmac");
        final PKIMessage req = genCertReq("C=SE,O=PrimeKey,CN=testRejectMissingExtraCertButExpectingHmac");

        final ArrayList<Certificate> signCertColl = new ArrayList<>();
        final byte[] messageBytes = CmpMessageHelper.signPKIMessage(req, signCertColl, keys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1,
                BouncyCastleProvider.PROVIDER_NAME);
        // Send CMP request
        final byte[] resp = sendCmpHttp(messageBytes, 200, ALIAS);
        // FIXME message from proxy was:
        // "Authentication failed for message. ExtraCerts field was blank, could not verify signature. CMP message: pvno = 2, sender = 4: C=SE,O=PrimeKey,CN=testRejectBadPayload, recipient = 4: CN=TestCA, transactionID = #4d6a225ea14f011959948a9181f3a46a."
        checkCmpFailMessage(resp, "Protection algorithm id expected '1.2.840.113533.7.66.13' (passwordBasedMac) but was '1.2.840.113549.1.1.5'.", PKIBody.TYPE_ERROR, 0, PKIFailureInfo.badRequest);
        shouldBeRejected();
        log.trace("<testRejectSignedButExpectingHmac");
    }

    @Test
    public void testVerifySignedMessage() throws Exception {
        log.trace(">testVerifySignedMessage");
        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(ALIAS, testx509ca.getName());
        cmpConfiguration.setResponseProtection(ALIAS, "signature");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);

        final X509Certificate signingCertificate = createSigningCertificate();
        final PKIMessage req = genCertReq("C=SE,O=PrimeKey,CN=testVerifySignedMessage");

        final ArrayList<Certificate> signCertColl = new ArrayList<>();
        signCertColl.add(signingCertificate);
        final byte[] messageBytes = CmpMessageHelper.signPKIMessage(req, signCertColl, keys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1,
                BouncyCastleProvider.PROVIDER_NAME);
        // Send CMP request
        final byte[] resp = sendCmpHttp(messageBytes, 200, ALIAS);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDnX500, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpCertRepMessage(cmpConfiguration, ALIAS, userDnX500, cacert, resp, reqId);
        shouldBeAccepted();
        log.trace("<testVerifySignedMessage");
    }

    @Test
    public void testVerifySignedMessageClientMode() throws Exception {
        log.trace(">testVerifySignedMessageClientMode");
        cmpConfiguration.setRAMode(ALIAS, false);
        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(ALIAS, testx509ca.getName());
        cmpConfiguration.setExtractUsernameComponent(ALIAS, "UID");
        cmpConfiguration.setResponseProtection(ALIAS, "signature");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);

        final String clientUserDn = "C=SE,O=PrimeKey,CN=testVerifySignedMessageClientMode,UID="+CLIENT_MODE_ENDENTITY;
        createCmpUser(CLIENT_MODE_ENDENTITY, PBEPASSWORD, clientUserDn, true, testx509ca.getCAId(), -1, -1);

        final X509Certificate signingCertificate = createSigningCertificate(ISSUER_DN, CLIENT_MODE_ENDENTITY, keys, caPrivateKey, CertificateConstants.CERT_ACTIVE, false);
        final PKIMessage req = genCertReq(clientUserDn);

        final ArrayList<Certificate> signCertColl = new ArrayList<>();
        signCertColl.add(signingCertificate);
        final byte[] messageBytes = CmpMessageHelper.signPKIMessage(req, signCertColl, keys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1,
                BouncyCastleProvider.PROVIDER_NAME);
        // Send CMP request
        final byte[] resp = sendCmpHttp(messageBytes, 200, ALIAS);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDnX500, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpCertRepMessage(cmpConfiguration, ALIAS, userDnX500, cacert, resp, reqId);
        shouldBeAccepted();
        log.trace("<testVerifySignedMessageClientMode");
    }

    /**
     * This test will verify that signed message passes through while bypassing any possible HMAC checks.
     */
    @Test
    public void testVerifySignedMessageWithHmacEnabled() throws Exception {
        log.trace(">testVerifySignedMessageWithHmacEnabled");
        final X509Certificate signingCertificate = createSigningCertificate();
        final PKIMessage req = genCertReq("C=SE,O=PrimeKey,CN=testVerifySignedMessageWithHmacEnabled");

        final ArrayList<Certificate> signCertColl = new ArrayList<>();
        signCertColl.add(signingCertificate);
        byte[] messageBytes = CmpMessageHelper.signPKIMessage(req, signCertColl, keys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1,
                BouncyCastleProvider.PROVIDER_NAME);
        // Send CMP request
        byte[] resp = sendCmpHttp(messageBytes, 200, ALIAS);
        // XXX should the response really be unsigned? (signed=false)
        checkCmpResponseGeneral(resp, ISSUER_DN, userDnX500, cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpCertRepMessage(cmpConfiguration, ALIAS, userDnX500, cacert, resp, reqId);
        shouldBeAccepted();
        log.trace("<testVerifySignedMessageWithHmacEnabled");
    }

    /**
     * This test will verify that a message protected by HMAC will pass when ca cmp ra shared secret is used
     */
    @Test
    public void testVerifyHmacProtectedMessageRaModeCaRaSharedSecret() throws Exception {
        log.trace(">testVerifyHmacProtectedMessageRaModeCaRaSharedSecret");
        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(ALIAS, "-");
        cmpConfiguration.setRAMode(ALIAS, true);
        cmpConfiguration.setResponseProtection(ALIAS, "signature");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
        final String userDn = "C=SE,O=PrimeKey,CN=testHMACProtectionRaModeUser";
        final String caRaSharedSecret = "foo123";
        final PKIMessage req = genCertReq(userDn);
        final byte[] messageBytes = CmpMessageHelper.protectPKIMessageWithPBE(req, testx509ca.getName(), caRaSharedSecret, "1.3.14.3.2.26", "1.3.6.1.5.5.8.1.2", 1024);
        // Send CMP request
        final byte[] resp = sendCmpHttp(messageBytes, 200, ALIAS);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDnX500, cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId());
        checkCmpCertRepMessage(cmpConfiguration, ALIAS, userDnX500, cacert, resp, reqId);
        shouldBeAccepted();
        log.trace("<testVerifyHmacProtectedMessageRaModeCaRaSharedSecret");
    }
    
    /**
     * This test will verify that a message protected by HMAC will pass when secret is specified in alias
     */
    @Test
    public void testVerifyHmacProtectedMessageRaModeAliasSpecifiedSecret() throws Exception {
        log.trace(">testVerifyHmacProtectedMessageRaModeAliasSpecifiedSecret");
        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(ALIAS, PBEPASSWORD);
        cmpConfiguration.setRAMode(ALIAS, true);
        cmpConfiguration.setResponseProtection(ALIAS, "signature");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
        final String userDn = "C=SE,O=PrimeKey,CN=testHMACProtectionRaModeUser";
        final PKIMessage req = genCertReq(userDn);
        final byte[] messageBytes = CmpMessageHelper.protectPKIMessageWithPBE(req, testx509ca.getName(), PBEPASSWORD, "1.3.14.3.2.26", "1.3.6.1.5.5.8.1.2", 1024);
        // Send CMP request
        final byte[] resp = sendCmpHttp(messageBytes, 200, ALIAS);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDnX500, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId());
        checkCmpCertRepMessage(cmpConfiguration, ALIAS, userDnX500, cacert, resp, reqId);
        shouldBeAccepted();
        log.trace("<testVerifyHmacProtectedMessageRaModeAliasSpecifiedSecret");
    }

    
    /**
     * This test will verify that a message protected by HMAC is rejected if passwords don't match
     */
    @Test
    public void testRejectHmacProtectedMessage() throws Exception {
        log.trace(">testRejectHmacProtectedMessage");
        final String incorrectPassword = "bar123";
        final PKIMessage req = genCertReq("C=SE,O=PrimeKey,CN=testRejectHmacProtectedMessage");
        final byte[] messageBytes = CmpMessageHelper.protectPKIMessageWithPBE(req, ISSUER_CA_NAME, incorrectPassword, "1.3.14.3.2.26", "1.3.6.1.5.5.8.1.2", 1024);
        // Send CMP request
        final byte[] resp = sendCmpHttp(messageBytes, 200, ALIAS);
        checkCmpFailMessage(resp, "Authentication failed for message. Failed to verify message using both Global Shared Secret and CMP RA Authentication Secret.", PKIBody.TYPE_ERROR, 0, PKIFailureInfo.badRequest);
        shouldBeRejected();
        log.trace("<testRejectHmacProtectedMessage");
    }

    /**
     * This test will verify that a message signed with the wrong certificate is rejected
     */
    @Test
    public void testRejectSignedMessageWithWrongCertificate() throws Exception {
        log.trace(">testRejectSignedMessageWithWrongCertificate");

        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(ALIAS, testx509ca.getName());
        cmpConfiguration.setResponseProtection(ALIAS, "signature");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);

        final KeyPair incorrectCaKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate signingCertificate = createSigningCertificate(ISSUER_DN, keys, incorrectCaKeys.getPrivate());
        final PKIMessage req = genCertReq("C=SE,O=PrimeKey,CN=testRejectSignedMessageWithWrongCertificate");

        final ArrayList<Certificate> signCertColl = new ArrayList<>();
        signCertColl.add(signingCertificate);
        final byte[] messageBytes = CmpMessageHelper.signPKIMessage(req, signCertColl, keys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1,
                BouncyCastleProvider.PROVIDER_NAME);
        // Send CMP request
        final byte[] resp = sendCmpHttp(messageBytes, 200, ALIAS);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDnX500, cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpFailMessage(resp, "Authentication failed for message. Invalid certificate or certificate not issued by specified CA: TrustAnchor found but certificate validation failed..", PKIBody.TYPE_ERROR, 0, PKIFailureInfo.badRequest);
        shouldBeRejected();
        log.trace("<testRejectSignedMessageWithWrongCertificate");
    }
    
    /**
     * This test will verify that a message signed with an expired certificate is rejected
     */
    @Test
    public void testMessageSignedByExpiredCertRejected() throws Exception {
        log.trace(">testMessageSignedByExpiredCertRejected");
        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(ALIAS, testx509ca.getName());
        cmpConfiguration.setResponseProtection(ALIAS, "signature");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);

        final X509Certificate signingCertificate = createSigningCertificate(ISSUER_DN, SIGNINGCERT_EE, keys, caPrivateKey, CertificateConstants.CERT_ACTIVE, true);
        final PKIMessage req = genCertReq("C=SE,O=PrimeKey,CN=testMessageSignedByExpiredCertRejected");

        final ArrayList<Certificate> signCertColl = new ArrayList<>();
        signCertColl.add(signingCertificate);
        final byte[] messageBytes = CmpMessageHelper.signPKIMessage(req, signCertColl, keys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1, BouncyCastleProvider.PROVIDER_NAME);
        // Send CMP request
        final byte[] resp = sendCmpHttp(messageBytes, 200, ALIAS);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDnX500, cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpFailMessage(resp, "Authentication failed for message. Invalid certificate or certificate not issued by specified CA: Could not validate certificate: certificate expired on 19700101000012GMT+00:00.", PKIBody.TYPE_ERROR, 0, PKIFailureInfo.badRequest);
        shouldBeRejected();
        log.trace("<testMessageSignedByExpiredCertRejected");
    }


    // TODO Enable if we add support for multiple CAs. Otherwise it should be removed.
//    /**
//     * This test will verify that signed message passes through. Will specifically check that multiple keychains can be specified and the right one picked.
//     */
//    @Test
//    public void testVerifySignedMessageWithMultipleExtraCertIssuers() throws Exception {
//        log.trace(">testVerifySignedMessageWithMultipleExtraCertIssuers");
//
//        final X509CA ca1 = CaTestUtils.createTestX509CA(ISSUER_1_DN, null, false, KEYUSAGE);
//        final X509Certificate ca1cert = (X509Certificate) ca1.getCACertificate();
//        final String ca1fp = CertTools.getFingerprintAsString(ca1cert);
//        final PrivateKey ca1PrivateKey = CaTestUtils.getCaPrivateKey(ca1);
//        caSession.addCA(ADMIN, ca1);
//
//        final X509CA ca2 = CaTestUtils.createTestX509CA(ISSUER_2_DN, null, false, KEYUSAGE);
//        final X509Certificate ca2cert = (X509Certificate) ca2.getCACertificate();
//        final String ca2fp = CertTools.getFingerprintAsString(ca2cert);
//        final PrivateKey ca2PrivateKey = CaTestUtils.getCaPrivateKey(ca2);
//        caSession.addCA(ADMIN, ca2);
//
//        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
//        cmpConfiguration.setAuthenticationParameters(ALIAS, testx509ca.getName());
//        cmpConfiguration.setResponseProtection(ALIAS, "signature");
//        cmpConfiguration.setRACAName(ALIAS, ISSUER_CA_1_NAME + ";" + ISSUER_CA_2_NAME); // <--- there is currently no way to have multiple RA CA's
//        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
//
//        final X509Certificate signingCertificate = createSigningCertificate(ISSUER_2_DN, keys, ca2PrivateKey);
//        final PKIMessage req = genCertReq("C=SE,O=PrimeKey,CN=testVerifySignedMessageWithMultipleExtraCertIssuers", ca2cert, ISSUER_2_DN);
//
//        final ArrayList<Certificate> signCertColl = new ArrayList<>();
//        signCertColl.add(signingCertificate);
//        final byte[] messageBytes = CmpMessageHelper.signPKIMessage(req, signCertColl, keys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1,
//                BouncyCastleProvider.PROVIDER_NAME);
//        // Send CMP request
//        final byte[] resp = sendCmpHttp(messageBytes, 200, ALIAS);
//        checkCmpResponseGeneral(resp, ISSUER_DN, userDnX500, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
//        checkCmpCertRepMessage(cmpConfiguration, ALIAS, userDnX500, cacert, resp, reqId);
//        shouldBeAccepted();
//        log.trace("<testVerifySignedMessageWithMultipleExtraCertIssuers");
//    }

    /**
     * This test will verify that signed message passes through. The main goal of this test is to assert the correct return code.
     */
    @Test
    public void testMessageSignedByRevokedCertRejected() throws Exception {
        log.trace(">testMessageSignedByRevokedCertRejected");
        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(ALIAS, testx509ca.getName());
        cmpConfiguration.setResponseProtection(ALIAS, "signature");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);

        final X509Certificate signingCertificate = createSigningCertificate(ISSUER_DN, SIGNINGCERT_EE, keys, caPrivateKey, CertificateConstants.CERT_REVOKED, false);
        final PKIMessage req = genCertReq("C=SE,O=PrimeKey,CN=testVerifySignedByRevokedCertMessage");

        final ArrayList<Certificate> signCertColl = new ArrayList<>();
        signCertColl.add(signingCertificate);
        final byte[] messageBytes = CmpMessageHelper.signPKIMessage(req, signCertColl, keys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1,
                BouncyCastleProvider.PROVIDER_NAME);
        // Send CMP request
        final byte[] resp = sendCmpHttp(messageBytes, 200, ALIAS);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDnX500, cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpFailMessage(resp, "Authentication failed for message. Signing certificate in CMP message was revoked.", PKIBody.TYPE_ERROR, 0, PKIFailureInfo.badRequest);
        shouldBeRejected();
        log.trace("<testMessageSignedByRevokedCertRejected");
    }


    /** Checks that the request was accepted (and would have been passed to the CA in a RA-CA setup) */
    private void shouldBeAccepted() {
        checkCalled("isAuthorizedNoLogging");
        checkCalled("cmpDispatch"); // Request should be passed to RA Master API
    }

    /** Checks that the request was blocked  (and would NOT had been passed to the CA in a RA-CA setup) */
    private void shouldBeRejected() {
        checkCalled("isAuthorizedNoLogging"); // Always called. Sanity check.
        checkNotCalled("cmpDispatch");
    }

    private void checkCalled(final String methodName) {
        final List<String> calledMethods = testRaMasterApiProxyBean.getFunctionTraceForTest();
        assertTrue("Method '" + methodName + "' should have been called",
                calledMethods.contains(methodName + RaMasterApiProxyBeanLocal.TEST_TRACE_SUFFIX_LOCAL) ||
                calledMethods.contains(methodName + RaMasterApiProxyBeanLocal.TEST_TRACE_SUFFIX_REMOTE));
    }

    private void checkNotCalled(final String methodName) {
        final List<String> calledMethods = testRaMasterApiProxyBean.getFunctionTraceForTest();
        assertFalse("Method '" + methodName + "' should NOT have been called", calledMethods.contains(methodName + RaMasterApiProxyBeanLocal.TEST_TRACE_SUFFIX_LOCAL));
        assertFalse("Method '" + methodName + "' (remote) should not have been called", calledMethods.contains(methodName + RaMasterApiProxyBeanLocal.TEST_TRACE_SUFFIX_REMOTE));
    }

    private X509Certificate createSigningCertificate() throws Exception {
        return createSigningCertificate(ISSUER_DN, keys, caPrivateKey);
    }

    private X509Certificate createSigningCertificate(final String issuerDn, final KeyPair signingKeyPair, final PrivateKey issuerKey) throws Exception {
        return createSigningCertificate(issuerDn, SIGNINGCERT_EE, signingKeyPair, issuerKey, CertificateConstants.CERT_ACTIVE, false);
    }

    private X509Certificate createSigningCertificate(final String issuerDn, final String username, final KeyPair signingKeyPair, final PrivateKey issuerKey, 
            final int certStatus, boolean isExpired) throws Exception {
        // Create the signing certificate, signed by the ca certificate
        Date firstDate = new Date();
        Date lastDate = new Date();
        if (isExpired) {
            firstDate.setTime(10000);
            lastDate.setTime(12000);
        } else {
            firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));
            lastDate.setTime(lastDate.getTime() + (24 * 60 * 60 * 1000));
        }
        byte[] serno = new byte[8];
        // This is a test, so randomness does not have to be secure (CSPRNG)
        Random random = new Random();
        random.nextBytes(serno);
        final SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(signingKeyPair.getPublic().getEncoded());
        X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name(issuerDn, false),
                new BigInteger(serno).abs(), firstDate, lastDate, CertTools.stringToBcX500Name(SIGNINGCERT_DN, false), pkinfo);
        final ContentSigner signer = new BufferingContentSigner(
                new JcaContentSignerBuilder("SHA256WithRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerKey), 20480);
        final X509CertificateHolder certHolder = certbuilder.build(signer);
        final X509Certificate cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
        assertNotNull("Certificate was null", cert);
        certificateStoreSession.storeCertificateRemote(ADMIN, EJBTools.wrap(cert), username, cafp, certStatus,
                CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateConstants.NO_CRL_PARTITION, null, System.currentTimeMillis(), null);
        grantAccessToCert(cert);
        return cert;
    }


    private void grantAccessToCert(final Certificate cert) throws Exception {
        roleSession.deleteRoleIdempotent(ADMIN, null, TEST_ROLE);
        final List<String> accessRules = Arrays.asList(
                AccessRulesConstants.REGULAR_CREATEENDENTITY,
                AccessRulesConstants.REGULAR_EDITENDENTITY,
                AccessRulesConstants.REGULAR_CREATECERTIFICATE,
                AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepDnOverrideId + AccessRulesConstants.CREATE_END_ENTITY,
                AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepDnOverrideId + AccessRulesConstants.EDIT_END_ENTITY,
                StandardRules.CAACCESS.resource() + testx509ca.getCAId());
        final Role role = roleSession.persistRole(ADMIN, new Role(null, TEST_ROLE, accessRules, Collections.emptyList()));
        roleMemberSession.persist(ADMIN, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, testx509ca.getCAId(), RoleMember.NO_PROVIDER,
                X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN"), role.getRoleId(), null));
    }

    private PKIMessage genCertReq(final String userDn) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {
        return genCertReq(userDn, cacert, ISSUER_DN);
    }

    private PKIMessage genCertReq(final String userDn, final X509Certificate issuerCert, final String issuerDn) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        this.nonce = nonce;
        this.transid = transid;
        userDnX500 = new X500Name(userDn);
        final PKIMessage req = genCertReq(issuerDn, userDnX500, keys, issuerCert, nonce, transid, false, null, null, null, null, null, null);
        final CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        return req;
    }

}
