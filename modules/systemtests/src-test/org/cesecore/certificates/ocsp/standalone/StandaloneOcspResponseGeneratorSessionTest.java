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
package org.cesecore.certificates.ocsp.standalone;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionRemote;
import org.cesecore.certificates.ocsp.OcspResponseInformation;
import org.cesecore.certificates.ocsp.OcspTestUtils;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.junit.util.CryptoTokenRule;
import org.cesecore.junit.util.CryptoTokenTestRunner;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.NullCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;

/**
 * Functional tests for StandaloneOcspResponseGeneratorSessionBean
 * 
 * @version $Id$
 * 
 */
@RunWith(CryptoTokenTestRunner.class)
public class StandaloneOcspResponseGeneratorSessionTest {
   
    private static final String TESTCLASSNAME = StandaloneOcspResponseGeneratorSessionTest.class.getSimpleName();
    private static final Logger log = Logger.getLogger(StandaloneOcspResponseGeneratorSessionTest.class);
 
    private String originalSigningTruststoreValidTime;

    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateCreateSessionRemote.class);
    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
    private final OcspResponseGeneratorSessionRemote ocspResponseGeneratorSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspResponseGeneratorSessionRemote.class);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASSNAME);
    
    private X509CA x509ca;
    private int internalKeyBindingId;
    private int cryptoTokenId;
    private X509Certificate ocspSigningCertificate;
    private X509Certificate caCertificate;   
    private static String originalDefaultResponder;
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
        GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        originalDefaultResponder = ocspConfiguration.getOcspDefaultResponderReference();
    }
    
    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    @ClassRule
    public static CryptoTokenRule cryptoTokenRule = new CryptoTokenRule();
   
    @Before
    public void setUp() throws Exception {
        x509ca = cryptoTokenRule.createX509Ca(); 
        originalSigningTruststoreValidTime = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.SIGNING_TRUSTSTORE_VALID_TIME);
        //Make sure timers don't run while we debug
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNING_TRUSTSTORE_VALID_TIME, Integer.toString(Integer.MAX_VALUE/1000));
        //Create an independent cryptotoken
        cryptoTokenId = cryptoTokenRule.createCryptoToken();
        internalKeyBindingId = OcspTestUtils.createInternalKeyBinding(authenticationToken, cryptoTokenId, OcspKeyBinding.IMPLEMENTATION_ALIAS,
                TESTCLASSNAME, "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        String signerDN = "CN=ocspTestSigner";
        caCertificate = (X509Certificate) x509ca.getCACertificate();
        ocspSigningCertificate = OcspTestUtils.createOcspSigningCertificate(authenticationToken, OcspTestUtils.OCSP_END_USER_NAME, signerDN, internalKeyBindingId, x509ca.getCAId());
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNATUREREQUIRED, "false");
    }

    @After
    public void tearDown() throws Exception {
        cryptoTokenRule.cleanUp();
        try {
            internalCertificateStoreSession.removeCertificate(ocspSigningCertificate);
        } catch (Exception e) {
            //Ignore any failures.
        }
        internalKeyBindingMgmtSession.deleteInternalKeyBinding(authenticationToken, internalKeyBindingId);
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNING_TRUSTSTORE_VALID_TIME, originalSigningTruststoreValidTime);
        // Make sure default responder is restored
        setOcspDefaultResponderReference(originalDefaultResponder);
    }

    /**
     * Behavior when a CA is renewed using a new key pair, but using the same subject DN.
     * 
     * This test also acts as "documentation" of how an OCSP responder should be configured to be able to continuously respond
     * for such an EE certificate even after the CA has been renewed.
     * (Spoiler: you need to issue a long lived OSCP signing certificate before the CA renewal.)
     */
    @Test
    public void testOcspSignerIssuerRenewal() throws Exception {
        final EndEntityInformation user = new EndEntityInformation("testOcspSignerIssuerRenewal", "CN=testOcspSignerIssuerRenewal", x509ca.getCAId(), null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setPassword("foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
        X509Certificate eeCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(authenticationToken, user, req,
                X509ResponseMessage.class, signSession.fetchCertGenParams())).getCertificate());
        
        setOcspDefaultResponderReference(null);
        try {
            activateKeyBinding(internalKeyBindingId);
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            assertEquals("Status is not null (good)", null, testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificate, ocspSigningCertificate, OCSPResp.SUCCESSFUL, true));
            // Try the same thing after CA has been renewed
            caAdminSession.renewCA(authenticationToken, x509ca.getCAId(), true, null, false);
            final X509Certificate caCertificateRenewed = (X509Certificate) caSession.getCAInfo(authenticationToken, x509ca.getCAId()).getCertificateChain().iterator().next();
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            /*
             * Since OCSP singing chain leads up to the previous CA certificate, the OCSP key binding exists for "this" CA.
             * Hence the result should be signed with the OCSP key binding leading up to the old CA cert.
             */
            assertEquals("Status is not null (good)", null, testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificate, ocspSigningCertificate, OCSPResp.SUCCESSFUL, true));
            /*
             * Since OCSP singing chain leads up to the previous CA certificate and the new CA exists,
             * the result will currently be signed by the CA itself.
             */
            assertEquals("Status is not null (good)", null, testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificateRenewed, caCertificateRenewed, OCSPResp.SUCCESSFUL, true));
            // Setup an additional key binding for later use before we delete the CA
            int internalKeyBindingIdNew = 0;
            X509Certificate ocspSigningCertificateNew = null;
            try {
                internalKeyBindingIdNew = OcspTestUtils.createInternalKeyBinding(authenticationToken, cryptoTokenId, OcspKeyBinding.IMPLEMENTATION_ALIAS,
                        TESTCLASSNAME+"2", "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
                String signerDN = "CN=ocspTestSigner2";
                ocspSigningCertificateNew = OcspTestUtils.createOcspSigningCertificate(authenticationToken, OcspTestUtils.OCSP_END_USER_NAME, signerDN, internalKeyBindingIdNew, x509ca.getCAId());
                // Delete the CA to make the signer "stand alone"
                OcspTestUtils.deleteCa(authenticationToken, x509ca);
                ocspResponseGeneratorSession.reloadOcspSigningCache();
                /*
                 * Since OCSP singing chain leads up to the previous CA certificate, the OCSP key binding exists for "this" CA.
                 * Hence the result should be signed with the OCSP key binding leading up to the old CA cert.
                 */
                assertEquals("Status is not null (good)", null, testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificate, ocspSigningCertificate, OCSPResp.SUCCESSFUL, true));
                /*
                 * Since OCSP singing chain leads up to the previous CA certificate and this CA does not exist,
                 * the result will be signed by the OCSP key binding leading up to the old CA.
                 * 
                 * NOTE: This only makes sense if the client is smart enough to also verify the signer against the old CA certificate.
                 */
                assertEquals("Status is not null (good)", null, testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificateRenewed, ocspSigningCertificate, OCSPResp.SUCCESSFUL, false));
                final String ocspSigningCertificateFingerprint = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(authenticationToken, internalKeyBindingIdNew);
                if (!CertTools.getFingerprintAsString(ocspSigningCertificateNew).equals(ocspSigningCertificateFingerprint)) {
                    throw new Error("Wrong certificate was found for InternalKeyBinding");
                }
                OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingIdNew, InternalKeyBindingStatus.ACTIVE);
                ocspResponseGeneratorSession.reloadOcspSigningCache();
                // New chain should be used
                assertEquals("Status is not null (good)", null, testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificateRenewed, ocspSigningCertificateNew, OCSPResp.SUCCESSFUL, true));
                // Old chain should still be used
                assertEquals("Status is not null (good)", null, testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificate, ocspSigningCertificate, OCSPResp.SUCCESSFUL, true));
                // Disable old signer now
                OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.DISABLED);
                ocspResponseGeneratorSession.reloadOcspSigningCache();
                // New chain should work
                assertEquals("Status is not null (good)", null, testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificateRenewed, ocspSigningCertificateNew, OCSPResp.SUCCESSFUL, true));
                /*
                 * Requests for the old CA certificate as issuer no longer has a valid responder and there is no default.
                 * 
                 * NOTE: A client that only has the EE certificate chain would at this point have no way to check OCSP anymore.
                 */
                testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificate, null, OCSPResp.UNAUTHORIZED, false);
            } finally {
                try {
                    internalCertificateStoreSession.removeCertificate(ocspSigningCertificateNew);
                } catch (Exception e) {
                    //Ignore any failures.
                }
                internalKeyBindingMgmtSession.deleteInternalKeyBinding(authenticationToken, internalKeyBindingIdNew);

            }
        } finally {
            internalCertificateStoreSession.removeCertificate(eeCertificate.getSerialNumber());
        }
    }
    
    private CertificateStatus testOcspSignerIssuerRenewalInternal(X509Certificate eeCertificate, X509Certificate caCertificate, X509Certificate expectedSigningCertificate, int expectedStatus, boolean shouldVerify) throws Exception {
        log.debug("EE Subject: " + CertTools.getSubjectDN(eeCertificate));
        log.debug("EE Issuer:  " + CertTools.getIssuerDN(eeCertificate));
        final OCSPReq ocspRequest = buildOcspRequest(null, null, caCertificate, eeCertificate.getSerialNumber());
        final OCSPResp response = sendRequest(ocspRequest);
        if (expectedStatus == OCSPResp.UNAUTHORIZED) {
            assertEquals("Response status not zero.", OCSPResp.UNAUTHORIZED, response.getStatus());
            return null;
        } else {
            assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
            BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
            List<X509Certificate> signingChain = CertTools.convertToX509CertificateList(Arrays.asList(basicOcspResponse.getCerts()));
            log.debug("signingChain.size: " + signingChain.size());
            final X509Certificate actualSignerCertificate = signingChain.get(0);
            log.debug("Subject: " + CertTools.getSubjectDN(actualSignerCertificate));
            log.debug("Issuer:  " + CertTools.getIssuerDN(actualSignerCertificate));
            assertEquals("Response was not signed by the expected certificate.", CertTools.getFingerprintAsString(expectedSigningCertificate), CertTools.getFingerprintAsString(actualSignerCertificate));
            assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(expectedSigningCertificate.getPublicKey())));
            try {
                CertTools.verify(actualSignerCertificate, Arrays.asList(new X509Certificate[] {caCertificate}));
                assertTrue("", shouldVerify);
            } catch (CertPathValidatorException e) {
                assertFalse("Please update the test when the responder improvement after renewal has improved.", shouldVerify);
            }
            SingleResp[] singleResponses = basicOcspResponse.getResponses();
            assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
            assertEquals("Response cert did not match up with request cert", eeCertificate.getSerialNumber(), singleResponses[0].getCertID().getSerialNumber());
            return singleResponses[0].getCertStatus();
        }
    }

    /** Tests the basic case of a standalone OCSP installation, i.e where this is a classic VA */
    @Test
    public void testStandAloneOcspResponseSanity() throws Exception {
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        ocspResponseGeneratorSession.reloadOcspSigningCache();
        // Do the OCSP request
        final OCSPReq ocspRequest = buildOcspRequest(null, null, caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp response = sendRequest(ocspRequest);
        assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
        validateSuccessfulResponse((BasicOCSPResp) response.getResponseObject(), ocspSigningCertificate.getPublicKey());
    }

    /** 
     * Tests the case of a standalone OCSP responder with a revoked certificate
     */
    @Test
    public void testResponseWithRevokedResponder() throws Exception {
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        //Revoke the responder cert
        internalCertificateStoreSession.setRevokeStatus(authenticationToken, ocspSigningCertificate, new Date(), RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
        ocspResponseGeneratorSession.reloadOcspSigningCache();
        // Do the OCSP request
        final OCSPReq ocspRequest = buildOcspRequest(null, null, caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp response = sendRequest(ocspRequest);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspSigningCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        Object status = singleResponses[0].getCertStatus();
        assertTrue("Status is not RevokedStatus", status instanceof RevokedStatus);
        RevokedStatus rev = (RevokedStatus) status;
        assertTrue("Status does not have reason", rev.hasRevocationReason());
        int reason = rev.getRevocationReason();
        assertEquals("Wrong revocation reason", reason, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
    }
    
    /** 
     * Tests the case of a stand-alone OCSP responder with a revoked certificate issuer using the keyCompromise reason code.
     * 
     * This should respond revoked, as from the RFC:
     * 
     *  If an OCSP responder knows that a particular CA's private key has
     *  been compromised, it MAY return the revoked state for all
     *  certificates issued by that CA.
     */
    @Test
    public void testResponseWithRevokedResponderIssuerKeyCompromise() throws Exception {
        testResponseWithRevokedResponderIssuer(RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE);
    }
    @Test
    public void testResponseWithRevokedResponderIssuerCaCompromise() throws Exception {
        testResponseWithRevokedResponderIssuer(RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE);
    }
    @Test
    public void testResponseWithRevokedResponderIssuerAaCompromise() throws Exception {
        testResponseWithRevokedResponderIssuer(RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE, RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE);
    }
    @Test
    public void testResponseWithRevokedResponderIssuerUnspecifiedReason() throws Exception {
        testResponseWithRevokedResponderIssuer(RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE);
    }

    /** 
     * Tests the case of a stand-alone OCSP responder with a revoked certificate issuer using the cessationOfOperation reason code.
     * 
     * This should not respond revoked, as from the RFC:
     * 
     *  If an OCSP responder knows that a particular CA's private key has
     *  been compromised, it MAY return the revoked state for all
     *  certificates issued by that CA.
     */
    @Test
    public void testResponseWithRevokedResponderIssuerAffiliationChanged() throws Exception {
        testResponseWithRevokedResponderIssuer(RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED, -1);
    }
    @Test
    public void testResponseWithRevokedResponderIssuerAffiliationCertificateHold() throws Exception {
        testResponseWithRevokedResponderIssuer(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, -1);
    }
    @Test
    public void testResponseWithRevokedResponderIssuerCessationOfOperation() throws Exception {
        testResponseWithRevokedResponderIssuer(RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION, -1);
    }
    @Test
    public void testResponseWithRevokedResponderIssuerAffiliationPrivilegesWithdrawn() throws Exception {
        testResponseWithRevokedResponderIssuer(RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN, -1);
    }
    @Test
    public void testResponseWithRevokedResponderIssuerAffiliationRemoveFromCrl() throws Exception {
        testResponseWithRevokedResponderIssuer(RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL, -1);
    }
    @Test
    public void testResponseWithRevokedResponderIssuerAffiliationSuperseded() throws Exception {
        testResponseWithRevokedResponderIssuer(RevokedCertInfo.REVOCATION_REASON_SUPERSEDED, -1);
    }

    private void testResponseWithRevokedResponderIssuer(final int caRevocationReason, final int expectedLeftRevocationCode) throws Exception {
        final CertificateStatus status = getStatusResponseWithRevokedResponderIssuer(caRevocationReason);
        if (expectedLeftRevocationCode == -1) {
            assertFalse("Status is RevokedStatus even though the CA was revoked with a reason that would not lead us to suspect a private key compromise.", status instanceof RevokedStatus);
        } else {
            assertTrue("Status is not RevokedStatus", status instanceof RevokedStatus);
            final RevokedStatus revokedStatus = (RevokedStatus) status;
            assertTrue("Status does not have reason", revokedStatus.hasRevocationReason());
            final int reason = revokedStatus.getRevocationReason();
            assertEquals("Wrong revocation reason of leaf when the CA's private key has been compromised.", expectedLeftRevocationCode, reason);
        }
    }

    public CertificateStatus getStatusResponseWithRevokedResponderIssuer(final int caRevocationReason) throws Exception {
        // Delete the original CA, making this test completely stand-alone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        // Revoke the issuer certificate with the specified reason
        internalCertificateStoreSession.setRevokeStatus(authenticationToken, caCertificate, new Date(), caRevocationReason);
        ocspResponseGeneratorSession.reloadOcspSigningCache();
        // Do the OCSP request
        final OCSPReq ocspRequest = buildOcspRequest(null, null, caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp response = sendRequest(ocspRequest);
        final BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        final SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspSigningCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        return singleResponses[0].getCertStatus();
    }
        
    /** Tests using the default responder for external CAs for a good certificate. */
    @Test
    public void testResponseWithDefaultResponderForExternal() throws Exception {
        // Make sure that a default responder is set
        setOcspDefaultResponderReference(CertTools.getIssuerDN(ocspSigningCertificate));
        //Make default responder standalone
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);      
        // Now, construct an external CA. 
        final String externalCaName = "testStandAloneOcspResponseExternalCa";
        final String externalCaSubjectDn = "CN=" + externalCaName;
        final long validity = 3650L;
        final String encodedValidity = "3650d";
        KeyPair externalCaKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate externalCaCertificate = CertTools.genSelfCert(externalCaSubjectDn, validity, null, externalCaKeys.getPrivate(),
                externalCaKeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        X509CAInfo externalCaInfo = new X509CAInfo(externalCaSubjectDn, externalCaName, CAConstants.CA_EXTERNAL,
                CertificateProfileConstants.CERTPROFILE_NO_PROFILE, encodedValidity, CAInfo.SELFSIGNED, null, null);
        CAToken token = new CAToken(externalCaInfo.getCAId(), new NullCryptoToken().getProperties());
        X509CA externalCa = new X509CA(externalCaInfo);
        externalCa.setCAToken(token);
        externalCa.setCertificateChain(Arrays.asList(externalCaCertificate));
        caSession.addCA(authenticationToken, externalCa);
        certificateStoreSession.storeCertificateRemote(authenticationToken, EJBTools.wrap(externalCaCertificate), externalCaName, "1234",
                CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ROOTCA,
                CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityInformation.NO_ENDENTITYPROFILE, null, new Date().getTime());
        ocspResponseGeneratorSession.reloadOcspSigningCache();
        try {
            final String externalUsername = "testStandAloneOcspResponseExternalUser";
            final String externalSubjectDn = "CN=" + externalUsername;
            // Create a certificate signed by the external CA and stuff it in the database (we can pretend it was imported)
            Date firstDate = new Date();
            firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));
            Date lastDate = new Date();
            lastDate.setTime(lastDate.getTime() + (24 * 60 * 60 * 1000));
            byte[] serno = new byte[8];
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(new Date().getTime());
            random.nextBytes(serno);
            KeyPair certificateKeyPair = KeyTools.genKeys("1024", "RSA");
            final SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(certificateKeyPair.getPublic().getEncoded());
            X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name(externalCaSubjectDn, false),
                    new BigInteger(serno).abs(), firstDate, lastDate, CertTools.stringToBcX500Name(externalSubjectDn, false), pkinfo);
            final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder("SHA256WithRSA").setProvider(
                    BouncyCastleProvider.PROVIDER_NAME).build(externalCaKeys.getPrivate()), 20480);
            final X509CertificateHolder certHolder = certbuilder.build(signer);
            X509Certificate importedCertificate = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
            certificateStoreSession.storeCertificateRemote(authenticationToken, EJBTools.wrap(importedCertificate), externalUsername, "1234",
                    CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityInformation.NO_ENDENTITYPROFILE, null, new Date().getTime());
            try {
                //Now everything is in place. Perform a request, make sure that the default responder signed it. 
                final OCSPReq ocspRequest = buildOcspRequest(null, null, (X509Certificate) externalCaCertificate,
                        importedCertificate.getSerialNumber());
                final OCSPResp response = sendRequest(ocspRequest);
                assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
                final BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
                assertNotNull("Signed request generated null-response.", basicOcspResponse);
                assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(ocspSigningCertificate.getPublicKey())));
                final SingleResp[] singleResponses = basicOcspResponse.getResponses();
                assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
                assertEquals("Response cert did not match up with request cert", importedCertificate.getSerialNumber(), singleResponses[0].getCertID().getSerialNumber());
                assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
            } finally {
                internalCertificateStoreSession.removeCertificate(importedCertificate);
            }
        } finally {
            caSession.removeCA(authenticationToken, externalCa.getCAId());
            internalCertificateStoreSession.removeCertificate(externalCaCertificate);
        }
    }
    
    /** Tests using the default responder for external CAs for a good certificate. */
    @Test
    public void testResponseWithDefaultResponderForExternalNoDefaultSet() throws Exception {
        // Make sure that a default responder is set
        setOcspDefaultResponderReference("");
        String originalNoneExistingIsGood = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.NON_EXISTING_IS_GOOD);
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NON_EXISTING_IS_GOOD, "false");
        try {
            //Make default responder standalone
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);      
            // Now, construct an external CA. 
            final String externalCaName = "testStandAloneOcspResponseExternalCa";
            final String externalCaSubjectDn = "CN=" + externalCaName;
            final long validity = 3650L;
            final String encodedValidity = "3650d";
            KeyPair externalCaKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            Certificate externalCaCertificate = CertTools.genSelfCert(externalCaSubjectDn, validity, null, externalCaKeys.getPrivate(),
                    externalCaKeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
            X509CAInfo externalCaInfo = new X509CAInfo(externalCaSubjectDn, externalCaName, CAConstants.CA_EXTERNAL,
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE, encodedValidity, CAInfo.SELFSIGNED, null, null);
            CAToken token = new CAToken(externalCaInfo.getCAId(), new NullCryptoToken().getProperties());
            X509CA externalCa = new X509CA(externalCaInfo);
            externalCa.setCAToken(token);
            externalCa.setCertificateChain(Arrays.asList(externalCaCertificate));
            caSession.addCA(authenticationToken, externalCa);
            certificateStoreSession.storeCertificateRemote(authenticationToken, EJBTools.wrap(externalCaCertificate), externalCaName, "1234",
                    CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ROOTCA,
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityInformation.NO_ENDENTITYPROFILE, null, new Date().getTime());
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            try {
                final String externalUsername = "testStandAloneOcspResponseExternalUser";
                final String externalSubjectDn = "CN=" + externalUsername;
                // Create a certificate signed by the external CA and stuff it in the database (we can pretend it was imported)
                Date firstDate = new Date();
                firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));
                Date lastDate = new Date();
                lastDate.setTime(lastDate.getTime() + (24 * 60 * 60 * 1000));
                byte[] serno = new byte[8];
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                random.setSeed(new Date().getTime());
                random.nextBytes(serno);
                KeyPair certificateKeyPair = KeyTools.genKeys("1024", "RSA");
                final SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(certificateKeyPair.getPublic().getEncoded());
                X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name(externalCaSubjectDn, false),
                        new BigInteger(serno).abs(), firstDate, lastDate, CertTools.stringToBcX500Name(externalSubjectDn, false), pkinfo);
                final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder("SHA256WithRSA").setProvider(
                        BouncyCastleProvider.PROVIDER_NAME).build(externalCaKeys.getPrivate()), 20480);
                final X509CertificateHolder certHolder = certbuilder.build(signer);
                X509Certificate importedCertificate = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
                certificateStoreSession.storeCertificateRemote(authenticationToken, EJBTools.wrap(importedCertificate), externalUsername, "1234",
                        CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY,
                        CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityInformation.NO_ENDENTITYPROFILE, null, new Date().getTime());
                try {
                    //Now everything is in place. Perform a request, make sure that the default responder signed it. 
                    final OCSPReq ocspRequest = buildOcspRequest(null, null, (X509Certificate) externalCaCertificate,
                            importedCertificate.getSerialNumber());
                    final OCSPResp response = sendRequest(ocspRequest);                    
                    assertEquals("Response status not OCSPRespBuilder.UNAUTHORIZED.", response.getStatus(), OCSPRespBuilder.UNAUTHORIZED);
                    assertNull("Response should not have contained a response object.", response.getResponseObject());
                } finally {
                    internalCertificateStoreSession.removeCertificate(importedCertificate);
                }
            } finally {
                caSession.removeCA(authenticationToken, externalCa.getCAId());
                internalCertificateStoreSession.removeCertificate(externalCaCertificate);
            }
        } finally {
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NON_EXISTING_IS_GOOD, originalNoneExistingIsGood);
        }
    }
    
    /** Tests using the default responder for external CAs, tests with a revoked cert */
    @Test
    public void testResponseWithDefaultResponderForExternalRevoked() throws Exception {
        // Make sure that a default responder is set
        setOcspDefaultResponderReference(CertTools.getIssuerDN(ocspSigningCertificate));
        String originalNoneExistingIsGood = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.NON_EXISTING_IS_GOOD);
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NON_EXISTING_IS_GOOD, "false");
        try {
            //Make default responder standalone
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);      
            // Now, construct an external CA. 
            final String externalCaName = "testStandAloneOcspResponseExternalCa";
            final String externalCaSubjectDn = "CN=" + externalCaName;
            final long validity = 3650L;
            final String encodedValidity = "3650d";
            KeyPair externalCaKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            Certificate externalCaCertificate = CertTools.genSelfCert(externalCaSubjectDn, validity, null, externalCaKeys.getPrivate(),
                    externalCaKeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
            X509CAInfo externalCaInfo = new X509CAInfo(externalCaSubjectDn, externalCaName, CAConstants.CA_EXTERNAL,
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE, encodedValidity, CAInfo.SELFSIGNED, null, null);
            CAToken token = new CAToken(externalCaInfo.getCAId(), new NullCryptoToken().getProperties());
            X509CA externalCa = new X509CA(externalCaInfo);
            externalCa.setCAToken(token);
            externalCa.setCertificateChain(Arrays.asList(externalCaCertificate));
            caSession.addCA(authenticationToken, externalCa);
            certificateStoreSession.storeCertificateRemote(authenticationToken, EJBTools.wrap(externalCaCertificate), externalCaName, "1234",
                    CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ROOTCA,
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityInformation.NO_ENDENTITYPROFILE, null, new Date().getTime());
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            try {
                final String externalUsername = "testStandAloneOcspResponseExternalUser";
                final String externalSubjectDn = "CN=" + externalUsername;
                // Create a certificate signed by the external CA and stuff it in the database (we can pretend it was imported)
                Date firstDate = new Date();
                firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));
                Date lastDate = new Date();
                lastDate.setTime(lastDate.getTime() + (24 * 60 * 60 * 1000));
                byte[] serno = new byte[8];
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                random.setSeed(new Date().getTime());
                random.nextBytes(serno);
                KeyPair certificateKeyPair = KeyTools.genKeys("1024", "RSA");
                final SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(certificateKeyPair.getPublic().getEncoded());                  
                X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name(externalCaSubjectDn, false),
                        new BigInteger(serno).abs(), firstDate, lastDate, CertTools.stringToBcX500Name(externalSubjectDn, false), pkinfo);
                final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder("SHA256WithRSA").setProvider(
                        BouncyCastleProvider.PROVIDER_NAME).build(externalCaKeys.getPrivate()), 20480);
                final X509CertificateHolder certHolder = certbuilder.build(signer);
                X509Certificate importedCertificate = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
                certificateStoreSession.storeCertificateRemote(authenticationToken, EJBTools.wrap(importedCertificate), externalUsername, "1234",
                        CertificateConstants.CERT_REVOKED, CertificateConstants.CERTTYPE_ENDENTITY,
                        CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityInformation.NO_ENDENTITYPROFILE, null, new Date().getTime());
                try {
                    //Now everything is in place. Perform a request, make sure that the default responder signed it. 
                    final OCSPReq ocspRequest = buildOcspRequest(null, null, (X509Certificate) externalCaCertificate,
                            importedCertificate.getSerialNumber());
                    final OCSPResp response = sendRequest(ocspRequest);
                    assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
                    final BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
                    assertNotNull("Signed request generated null-response.", basicOcspResponse);
                    assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(ocspSigningCertificate.getPublicKey())));
                    final SingleResp[] singleResponses = basicOcspResponse.getResponses();
                    assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
                    assertEquals("Response cert did not match up with request cert", importedCertificate.getSerialNumber(), singleResponses[0].getCertID().getSerialNumber());
                    assertTrue("Status is not revoked", singleResponses[0].getCertStatus() instanceof RevokedStatus );
                } finally {
                    internalCertificateStoreSession.removeCertificate(importedCertificate);
                }
            } finally {
                caSession.removeCA(authenticationToken, externalCa.getCAId());
                internalCertificateStoreSession.removeCertificate(externalCaCertificate);
            }
        } finally {
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NON_EXISTING_IS_GOOD, originalNoneExistingIsGood);
        }
    }
    
    /**
     * This tests the use case where a key binding has been added but the cache hasn't been updated yet, due to long update times.
     * OcspResponseGeneratorSession should handle this without problems. 
     */
    @Test
    public void testCacheMissHandling() throws Exception {
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        ocspResponseGeneratorSession.reloadOcspSigningCache();
        activateKeyBinding(internalKeyBindingId);
        final OCSPReq ocspRequest = buildOcspRequest(null, null, caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp response = sendRequest(ocspRequest);
        assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
        validateSuccessfulResponse((BasicOCSPResp) response.getResponseObject(), ocspSigningCertificate.getPublicKey());
    }
    
    /** Tests asking about an unknown CA, and making sure that the response is correctly signed */
    @Test
    public void testStandAloneOcspResponseDefaultResponder() throws Exception {
        // Make sure that a default responder is set
        setOcspDefaultResponderReference(CertTools.getIssuerDN(ocspSigningCertificate));
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.nonexistingisgood", "false");
        try {
              //Now delete the original CA, making this test completely standalone.
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            // Do the OCSP request
            final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            final X509Certificate fakeIssuerCertificate = CertTools.genSelfCert("CN=fakeCA", 365, null, keys.getPrivate(), keys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);       
            final BigInteger fakeSerialNumber = new BigInteger("4711");
            final OCSPReq ocspRequest = buildOcspRequest(null, null, fakeIssuerCertificate, fakeSerialNumber);
            final OCSPResp response = sendRequest(ocspRequest);
            assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
            BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
            //Response will be signed with the OCSP signing certificate, because that certificate's issuing CA was given as a default responder.
            assertTrue("OCSP response was not signed correctly.",
                    basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(ocspSigningCertificate.getPublicKey())));
            SingleResp[] singleResponses = basicOcspResponse.getResponses();
            assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
            assertEquals("Response cert did not match up with request cert", fakeSerialNumber, singleResponses[0].getCertID()
                    .getSerialNumber());
            assertTrue(singleResponses[0].getCertStatus() instanceof UnknownStatus);
        } finally {
            cesecoreConfigurationProxySession.setConfigurationValue("ocsp.nonexistingisgood", "false");
        }
    }
    
    /** Tests the case where there exists both a CA and a key binding for that CA on the same machine. The Key Binding should have priority. */
    @Test
    public void testStandAloneOcspResponseWithBothCaAndInternalKeyBinding() throws Exception {
        //Note: The CA never gets deleted in this test, so there exists both a CA and a key binding at the same time. 
        activateKeyBinding(internalKeyBindingId);
        ocspResponseGeneratorSession.reloadOcspSigningCache();
        // Do the OCSP request
        final OCSPReq ocspRequest = buildOcspRequest(null, null, caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp response = sendRequest(ocspRequest);
        assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
        validateSuccessfulResponse((BasicOCSPResp) response.getResponseObject(), ocspSigningCertificate.getPublicKey());
    }

    
    /** Test that trust settings are properly persisted */
    @Test
    public void testTrustPersistance() throws Exception {
        // Configure the OcspKeyBinding to require a signature (by any certificate)
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        ocspKeyBinding.setRequireTrustedSignature(true);
        addTrustEntry(ocspKeyBinding, -1, new BigInteger("3"));
        addTrustEntry(ocspKeyBinding, -2, null);
        addTrustEntry(ocspKeyBinding, x509ca.getCAId(), new BigInteger("0"));
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        // Clear caches must always be run over localhost and not through a configured proxy
        final int responseCode = ((HttpURLConnection) new URL("http://localhost:8080/ejbca/clearcache/?command=clearcaches").openConnection()).getResponseCode();
        assertEquals("Failed to invoked clear cache servlet.", HttpURLConnection.HTTP_OK, responseCode);
        final OcspKeyBinding ocspKeyBindingLoaded = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        assertTrue("RequireTrustedSignature setting was not persisted.", ocspKeyBindingLoaded.getRequireTrustedSignature());
        final List<InternalKeyBindingTrustEntry> trustEntries = ocspKeyBindingLoaded.getTrustedCertificateReferences();
        assertEquals("Not the same number of entries in list of trusted requestors", 3, trustEntries.size());
        boolean found = false;
        for (final InternalKeyBindingTrustEntry trustEntry : trustEntries) {
            log.debug("Comparing " + trustEntry.getCaId() + " " + trustEntry.fetchCertificateSerialNumber());
            if (trustEntry.getCaId() == x509ca.getCAId() && trustEntry.fetchCertificateSerialNumber() != null && trustEntry.fetchCertificateSerialNumber().equals(new BigInteger("0"))) {
                found = true;
            }
        }
        assertTrue("Configured trust entry was no longer present after cache flush", found);
        ocspResponseGeneratorSession.reloadOcspSigningCache();
    }

    /**
     * Request signature requirement: ANY known certificate.
     * Request signature:             None.
     * Expected outcome:              5 (OCSPResp.SIG_REQUIRED)
     */
    @Test
    public void testAnySignatureRequiredNoSignature() throws Exception {
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        // Configure the OcspKeyBinding to require a signature (by any certificate)
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        ocspKeyBinding.setRequireTrustedSignature(true);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        ocspResponseGeneratorSession.reloadOcspSigningCache();
        // Try to send an unsigned OCSP requests
        final OCSPReq ocspRequestUnsigned = buildOcspRequest(null, null, caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp ocspResponseUnsigned = sendRequest(ocspRequestUnsigned);
        assertEquals("We expected a 'Signature Required' status code: ", OCSPResp.SIG_REQUIRED, ocspResponseUnsigned.getStatus());
        assertNull("We expected the response object to be null when 'Signature Required' is received.", ocspResponseUnsigned.getResponseObject());
    }

    /**
     * Request signature requirement: None.
     * Request signature:             Present.
     * Expected outcome:              0 (OCSPResp.SUCCESSFUL)
     */
    @Test
    public void testNoSignatureRequiredButSignaturePresent() throws Exception {
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = Thread.currentThread().getStackTrace()[1].getMethodName();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername, ocspAuthenticationKeyPair.getPublic());
        try {
            //Now delete the original CA, making this test completely standalone.
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);
            // Configure the OcspKeyBinding to require a signature (by any certificate)
            final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                    internalKeyBindingId);
            ocspKeyBinding.setRequireTrustedSignature(false);
            internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            internalCertificateStoreSession.reloadCaCertificateCache();
            // Try to send a signed OCSP requests
            final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(), caCertificate,
                    ocspSigningCertificate.getSerialNumber());
            final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
            assertEquals("We expected a 'Successful' status code: ", OCSPResp.SUCCESSFUL, ocspResponseSigned.getStatus());
            validateSuccessfulResponse((BasicOCSPResp) ocspResponseSigned.getResponseObject(), ocspSigningCertificate.getPublicKey());
        } finally {
            internalCertificateStoreSession.removeCertificate(ocspAuthenticationCertificate);
        }
    }

    /**
     * Request signature requirement: ANY known certificate.
     * Request signature:             By a known certificate.
     * Expected outcome:              0 (OCSPResp.SUCCESSFUL)
     */
    @Test
    public void testAnySignatureRequiredSignature() throws Exception {
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = Thread.currentThread().getStackTrace()[1].getMethodName();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername,
                ocspAuthenticationKeyPair.getPublic());
        try {
            //Now delete the original CA, making this test completely standalone.
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);
            // Configure the OcspKeyBinding to require a signature (by any certificate)
            final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                    internalKeyBindingId);
            ocspKeyBinding.setRequireTrustedSignature(true);
            internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            internalCertificateStoreSession.reloadCaCertificateCache();
            // Try to send a signed OCSP requests
            final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(), caCertificate,
                    ocspSigningCertificate.getSerialNumber());
            final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
            assertEquals("We expected a 'Successful' status code: ", OCSPResp.SUCCESSFUL, ocspResponseSigned.getStatus());
            validateSuccessfulResponse((BasicOCSPResp) ocspResponseSigned.getResponseObject(), ocspSigningCertificate.getPublicKey());
        } finally {
            internalCertificateStoreSession.removeCertificate(ocspAuthenticationCertificate);
        }
    }
    
    /**
     * Request signature requirement: ANY certificate issued by a CA with caId=-1.
     * Request signature:             By a known certificate issued by a CA with caId!=-1.
     * Expected outcome:              6 (OCSPResp.UNAUTHORIZED)
     */
    @Test
    public void testSpecificIssuerSignatureRequiredWrongSignatureIssuer() throws Exception {
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = Thread.currentThread().getStackTrace()[1].getMethodName();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername,
                ocspAuthenticationKeyPair.getPublic());
        try {
            //Now delete the original CA, making this test completely standalone.
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);
            // Configure the OcspKeyBinding to require a signature (by any certificate)
            final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                    internalKeyBindingId);
            ocspKeyBinding.setRequireTrustedSignature(true);
            // Trust signatures from CA with id -1 (should not exist)
            addTrustEntry(ocspKeyBinding, -1, null);
            internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            // Try to send a signed OCSP requests
            final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(), caCertificate,
                    ocspSigningCertificate.getSerialNumber());
            final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
            assertEquals("We expected a 'Unauthorized' status code: ", OCSPResp.UNAUTHORIZED, ocspResponseSigned.getStatus());
            assertNull("Unauthorized signed request did not generate null-response.", ocspResponseSigned.getResponseObject());
        } finally {
            internalCertificateStoreSession.removeCertificate(ocspAuthenticationCertificate);
        }
    }
    
    /**
     * Request signature requirement: ANY certificate issued by a our test CA.
     * Request signature:             By a known certificate issued by our test CA.
     * Expected outcome:              0 (OCSPResp.SUCCESSFUL)
     */
    @Test
    public void testSpecificIssuerSignatureRequiredRightSignatureIssuer() throws Exception {
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = Thread.currentThread().getStackTrace()[1].getMethodName();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername,
                ocspAuthenticationKeyPair.getPublic());
        try {
            //Now delete the original CA, making this test completely standalone.
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);
            // Configure the OcspKeyBinding to require a signature
            final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                    internalKeyBindingId);
            ocspKeyBinding.setRequireTrustedSignature(true);
            // Trust signatures from our test CA
            addTrustEntry(ocspKeyBinding, x509ca.getCAId(), null);
            internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            internalCertificateStoreSession.reloadCaCertificateCache();
            // Try to send a signed OCSP requests
            final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(), caCertificate,
                    ocspSigningCertificate.getSerialNumber());
            final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
            assertEquals("Expected a 'Successful' status code: ", OCSPResp.SUCCESSFUL, ocspResponseSigned.getStatus());
            validateSuccessfulResponse((BasicOCSPResp) ocspResponseSigned.getResponseObject(), ocspSigningCertificate.getPublicKey());
        } finally {
            internalCertificateStoreSession.removeCertificate(ocspAuthenticationCertificate);
        }
    }
    
    /**
     * Request signature requirement: A certificate issued by a our test CA with certificate serialnumer=0.
     * Request signature:             By a known certificate issued by our test CA with certificate serialnumer!=0.
     * Expected outcome:              6 (OCSPResp.UNAUTHORIZED)
     */
    @Test
    public void testSpecificSignerSignatureRequiredWrongSignatureCert() throws Exception {
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = Thread.currentThread().getStackTrace()[1].getMethodName();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername,
                ocspAuthenticationKeyPair.getPublic());
        try {
            //Now delete the original CA, making this test completely standalone.
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);
            // Configure the OcspKeyBinding to require a signature (by any certificate)
            final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                    internalKeyBindingId);
            ocspKeyBinding.setRequireTrustedSignature(true);
            // Trust signatures from our test CA and certificate serial number "0" (that should be the one we are using)
            addTrustEntry(ocspKeyBinding, x509ca.getCAId(), new BigInteger("0"));
            internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            // Try to send a signed OCSP requests
            final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(), caCertificate,
                    ocspSigningCertificate.getSerialNumber());
            final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
            assertEquals("We expected a 'Unauthorized' status code: ", OCSPResp.UNAUTHORIZED, ocspResponseSigned.getStatus());
            assertNull("Unauthorized signed request did not generate null-response.", ocspResponseSigned.getResponseObject());
        } finally {
            internalCertificateStoreSession.removeCertificate(ocspAuthenticationCertificate);
        }
    }
    
    /**
     * Request signature requirement: A certificate issued by a our test CA with the certificate's serialnumber.
     * Request signature:             By the required certificate.
     * Expected outcome:              0 (OCSPResp.SUCCESSFUL)
     */
    @Test
    public void testSpecificSignerSignatureRequiredRightSignatureCert() throws Exception {
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = Thread.currentThread().getStackTrace()[1].getMethodName();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername,
                ocspAuthenticationKeyPair.getPublic());
        try {
            //Now delete the original CA, making this test completely standalone.
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);
            // Configure the OcspKeyBinding to require a signature
            final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                    internalKeyBindingId);
            ocspKeyBinding.setRequireTrustedSignature(true);
            // Trust signatures from our test CA and the certificate serial number from our auth cert
            addTrustEntry(ocspKeyBinding, x509ca.getCAId(), ocspAuthenticationCertificate.getSerialNumber());
            internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            internalCertificateStoreSession.reloadCaCertificateCache();
            // Try to send a signed OCSP requests
            final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(), caCertificate,
                    ocspSigningCertificate.getSerialNumber());
            final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
            assertEquals("We expected a 'Successful' status code: ", OCSPResp.SUCCESSFUL, ocspResponseSigned.getStatus());
            validateSuccessfulResponse((BasicOCSPResp) ocspResponseSigned.getResponseObject(), ocspSigningCertificate.getPublicKey());
        } finally {
            internalCertificateStoreSession.removeCertificate(ocspAuthenticationCertificate);
        }
    }
    
    /**
     * Request signature requirement: A certificate issued by a our test CA with the certificate's serialnumber.
     * Request signature:             By the required certificate, which happens to be revoked. 
     * Expected outcome:              UNAUTHORIZED
     */
    @Test
    public void testSpecificSignerSignatureRequiredRevokedSignatureCert() throws Exception {
        //Create a special issuer.
        X509CA signatureIssuerCa = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(authenticationToken,
                "CN=RevokedSignatureIssuer");
        int cryptoTokenId = signatureIssuerCa.getCAToken().getCryptoTokenId();
        cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, "signKeyAlias", "1024");
        X509Certificate signerIssuerCaCertificate = (X509Certificate) signatureIssuerCa.getCACertificate();
        //Store the CA Certificate.
        certificateStoreSession.storeCertificateRemote(authenticationToken, EJBTools.wrap(signerIssuerCaCertificate), "foo", "1234", CertificateConstants.CERT_ACTIVE,
                CertificateConstants.CERTTYPE_ROOTCA, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, EndEntityInformation.NO_ENDENTITYPROFILE, "footag", new Date().getTime());
        final String signatureRequired = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.SIGNATUREREQUIRED);
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNATUREREQUIRED, "true");

        try {
            final String ocspAuthenticationUsername = Thread.currentThread().getStackTrace()[1].getMethodName();
            final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
            final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(signatureIssuerCa.getCAId(),
                    ocspAuthenticationUsername, ocspAuthenticationKeyPair.getPublic());

            try {
                //Now delete the original CA, making this test completely standalone.
                OcspTestUtils.deleteCa(authenticationToken, x509ca);
                activateKeyBinding(internalKeyBindingId);
                // Configure the OcspKeyBinding to require a signature
                final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                        internalKeyBindingId);
                ocspKeyBinding.setRequireTrustedSignature(true);
                // Trust signatures from our test CA and the certificate serial number from our auth cert
                addTrustEntry(ocspKeyBinding, x509ca.getCAId(), ocspAuthenticationCertificate.getSerialNumber());
                internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
                ocspResponseGeneratorSession.reloadOcspSigningCache();
                internalCertificateStoreSession.reloadCaCertificateCache();
                // Try to send a signed OCSP requests
                final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(),
                        (X509Certificate) x509ca.getCACertificate() , ocspSigningCertificate.getSerialNumber());
                internalCertificateStoreSession.setRevokeStatus(authenticationToken, ocspAuthenticationCertificate, new Date(), RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
                final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
                assertEquals("We expected an 'UNAUTHORIZED' status code: ", OCSPResp.UNAUTHORIZED, ocspResponseSigned.getStatus());
             //   validateSuccessfulResponse((BasicOCSPResp) ocspResponseSigned.getResponseObject(), ocspSigningCertificate.getPublicKey());
            } finally {
                internalCertificateStoreSession.removeCertificate(ocspAuthenticationCertificate);
            }
        } finally {
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNATUREREQUIRED, signatureRequired);
            OcspTestUtils.deleteCa(authenticationToken, signatureIssuerCa);
        }
    }
    
    /**
     * Request signature requirement: Multiple options.
     * Request signature:             By a known certificate issued by our test CA, not matching any of the configured trust entries.
     * Expected outcome:              6 (OCSPResp.UNAUTHORIZED)
     */
    @Test
    public void testOneOfManySignatureRequiredWrongSignatureCert() throws Exception {
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = Thread.currentThread().getStackTrace()[1].getMethodName();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername, ocspAuthenticationKeyPair.getPublic());
        try {
            //Now delete the original CA, making this test completely standalone.
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);
            // Configure the OcspKeyBinding to require a signature
            final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                    internalKeyBindingId);
            ocspKeyBinding.setRequireTrustedSignature(true);
            // Trust signatures from our test CA and the certificate serial number from our auth cert
            addTrustEntry(ocspKeyBinding, -1, ocspAuthenticationCertificate.getSerialNumber());
            addTrustEntry(ocspKeyBinding, -2, null);
            addTrustEntry(ocspKeyBinding, x509ca.getCAId(), new BigInteger("0"));
            internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            // Try to send a signed OCSP requests
            final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(), caCertificate,
                    ocspSigningCertificate.getSerialNumber());
            final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
            assertEquals("We expected a 'Unauthorized' status code: ", OCSPResp.UNAUTHORIZED, ocspResponseSigned.getStatus());
            assertNull("Unauthorized signed request did not generate null-response.", ocspResponseSigned.getResponseObject());
        } finally {
            internalCertificateStoreSession.removeCertificate(ocspAuthenticationCertificate);
        }
    }
    
    /**
     * Request signature requirement: Multiple options where one is the CA and serialnumber of the issued authentication certificate.
     * Request signature:             By a known certificate issued by our test CA.
     * Expected outcome:              0 (OCSPResp.SUCCESSFUL)
     */
    @Test
    public void testOneOfManySignatureRequiredRightSignatureCert() throws Exception {
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = Thread.currentThread().getStackTrace()[1].getMethodName();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername,
                ocspAuthenticationKeyPair.getPublic());
        try {
            //Now delete the original CA, making this test completely standalone.
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);
            // Configure the OcspKeyBinding to require a signature
            final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                    internalKeyBindingId);
            ocspKeyBinding.setRequireTrustedSignature(true);
            // Trust signatures from our test CA and the certificate serial number from our auth cert
            addTrustEntry(ocspKeyBinding, -1, ocspAuthenticationCertificate.getSerialNumber());
            addTrustEntry(ocspKeyBinding, -2, null);
            addTrustEntry(ocspKeyBinding, x509ca.getCAId(), ocspAuthenticationCertificate.getSerialNumber());
            internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            internalCertificateStoreSession.reloadCaCertificateCache();
            // Try to send a signed OCSP requests
            final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(), caCertificate,
                    ocspSigningCertificate.getSerialNumber());
            final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
            assertEquals("We expected a 'Successful' status code: ", OCSPResp.SUCCESSFUL, ocspResponseSigned.getStatus());
            validateSuccessfulResponse((BasicOCSPResp) ocspResponseSigned.getResponseObject(), ocspSigningCertificate.getPublicKey());
        } finally {
            internalCertificateStoreSession.removeCertificate(ocspAuthenticationCertificate);
        }
    }
    
    /**
     * Tests the case where signature is required, but requester is not authorized to make it.
     */
    @Test
    public void testUnauthorizedRequester() throws Exception {
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = Thread.currentThread().getStackTrace()[1].getMethodName();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername,
                ocspAuthenticationKeyPair.getPublic());
        try {
            //Now delete the original CA, making this test completely standalone.
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);
            // Configure the OcspKeyBinding to require a signature
            final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                    internalKeyBindingId);
            ocspKeyBinding.setRequireTrustedSignature(true);
            // Trust signatures from our test CA and the certificate serial number from our auth cert
            addTrustEntry(ocspKeyBinding, 4711, new BigInteger("4711"));
            internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            internalCertificateStoreSession.reloadCaCertificateCache();
            // Try to send a signed OCSP requests
            final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(), caCertificate,
                    ocspSigningCertificate.getSerialNumber());
            final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
            assertEquals("We expected a 'Unauthorized' status code: ", OCSPResp.UNAUTHORIZED, ocspResponseSigned.getStatus());
        } finally {
            internalCertificateStoreSession.removeCertificate(ocspAuthenticationCertificate);

        }
    }
    
    
    @Test
    public void testGetOcspResponseWithIncorrectDefaultResponder() throws Exception {        
        // Set a fake value
        setOcspDefaultResponderReference("CN=FancyPants");
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNATUREREQUIRED, "true");
        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), ocspSigningCertificate, ocspSigningCertificate
                .getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        //Create a signed request in order to test all aspects 
        KeyPair keys = KeyTools.genKeys("512", "RSA");
        // Issue a certificate to a test user
        final String endEntityName = "testGetOcspResponseWithIncorrectDefaultResponder";
        final EndEntityInformation user = new EndEntityInformation(endEntityName, "CN="+endEntityName, x509ca.getCAId(), null, null,
                new EndEntityType(EndEntityTypes.ENDUSER), 1, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setStatus(EndEntityConstants.STATUS_NEW);
        user.setPassword("foo123");
        final SimpleRequestMessage certreq = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
        final X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(authenticationToken, user, certreq, X509ResponseMessage.class, signSession.fetchCertGenParams());
        final X509Certificate ocspTestCert = (X509Certificate)resp.getCertificate();

        X509CertificateHolder chain[] = new JcaX509CertificateHolder[2];
        chain[0] = new JcaX509CertificateHolder(ocspTestCert);
        chain[1] = new JcaX509CertificateHolder(caCertificate);
        gen.setRequestorName(chain[0].getSubject());
        OCSPReq req = gen.build(new BufferingContentSigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keys.getPrivate()), 20480), chain);
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        ocspResponseGeneratorSession.reloadOcspSigningCache();
        
        try {
            final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
            // Create the transaction logger for this transaction.
            TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
            // Create the audit logger for this transaction.
            AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
            byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger)
                    .getOcspResponse();
            //We're expecting back an unsigned reply saying unauthorized, as per RFC2690 Section 2.3
            assertNotNull("OCSP responder replied null", responseBytes);
            OCSPResp response = new OCSPResp(responseBytes);
            assertEquals("Response status not OCSPRespBuilder.UNAUTHORIZED.", response.getStatus(), OCSPRespBuilder.UNAUTHORIZED);
            assertNull("Response should not have contained a response object.", response.getResponseObject());
        } finally {
            try {
                if (ocspTestCert != null)
                    internalCertificateStoreSession.removeCertificate(ocspTestCert);
            } catch (Exception e) {
                //NOPMD: Ignore
            }
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNATUREREQUIRED, "false");
        }
    }
    
    @Test
    public void testOcspSignerWithCriticalEku() throws Exception {
        final List<Integer> authorizedCaIds = Arrays.asList(new Integer[]{Integer.valueOf(x509ca.getCAId())});
        final String certProfileCloneName = "testOcspSignerWithCriticalEku";
        certificateProfileSession.removeCertificateProfile(authenticationToken, certProfileCloneName);
        try {
            certificateProfileSession.cloneCertificateProfile(authenticationToken, "OCSPSIGNER", certProfileCloneName, authorizedCaIds);
            final int certificateProfileId = certificateProfileSession.getCertificateProfileId(certProfileCloneName);
            final CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(certProfileCloneName);
            certificateProfile.setExtendedKeyUsageCritical(true);
            certificateProfile.setExtendedKeyUsageOids(new ArrayList<String>(Arrays.asList(new String[]{KeyPurposeId.id_kp_OCSPSigning.getId()})));
            certificateProfileSession.changeCertificateProfile(authenticationToken, certProfileCloneName, certificateProfile);
            X509Certificate ocspSigningCertificate = null;
            try {
                ocspSigningCertificate = OcspTestUtils.createOcspSigningCertificate(authenticationToken, OcspTestUtils.OCSP_END_USER_NAME,
                        "CN=testOcspSignerWithCriticalEku", internalKeyBindingId, x509ca.getCAId(), certificateProfileId);
                assertNotNull("No EKU present.", ocspSigningCertificate.getExtendedKeyUsage());
                assertTrue("EKU was not critical", ocspSigningCertificate.getCriticalExtensionOIDs().contains(Extension.extendedKeyUsage.getId()));
                assertTrue("id_kp_OCSPSigning EKU not present", ocspSigningCertificate.getExtendedKeyUsage().contains(KeyPurposeId.id_kp_OCSPSigning.getId()));
                final String ocspSigningCertificateFingerprint = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(authenticationToken, internalKeyBindingId);
                if (!CertTools.getFingerprintAsString(ocspSigningCertificate).equals(ocspSigningCertificateFingerprint)) {
                    throw new Error("Wrong certificate was found for InternalKeyBinding");
                }
                OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
                ocspResponseGeneratorSession.reloadOcspSigningCache();
                // Make the request and check that the cert with critical EKU was picked up
                final OCSPReq ocspRequest = buildOcspRequest(null, null, caCertificate, ocspSigningCertificate.getSerialNumber());
                final OCSPResp ocspResponse = sendRequest(ocspRequest);
                assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, ocspResponse.getStatus());
                BasicOCSPResp basicOcspResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
                assertNotNull("Signed request generated null-response.", basicOcspResponse);
                assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(ocspSigningCertificate.getPublicKey())));
                final SingleResp[] singleResponses = basicOcspResponse.getResponses();
                assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
                assertEquals("Response cert did not match up with request cert", ocspSigningCertificate.getSerialNumber(), singleResponses[0].getCertID().getSerialNumber());
                assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
            } finally {
                if (ocspSigningCertificate!=null) {
                    internalCertificateStoreSession.removeCertificate(ocspSigningCertificate);
                    internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(authenticationToken, internalKeyBindingId);
                    OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
                    ocspResponseGeneratorSession.reloadOcspSigningCache();
                }
            }
        } finally {
            certificateProfileSession.removeCertificateProfile(authenticationToken, certProfileCloneName);
        }
    }
    
    // Trusting a certificateSerialNumber of null means any certificate from the CA
    private void addTrustEntry(InternalKeyBinding internalKeyBinding, int caId, BigInteger certificateSerialNumber) {
        final List<InternalKeyBindingTrustEntry> trustList = new ArrayList<InternalKeyBindingTrustEntry>(internalKeyBinding.getTrustedCertificateReferences());
        trustList.add(new InternalKeyBindingTrustEntry(caId, certificateSerialNumber));
        internalKeyBinding.setTrustedCertificateReferences(trustList);
    }
    
    /** Ask the OcspKeyBinding to search the database for the latest certificate matching its public key and set the status to ACTIVE */
    private void activateKeyBinding(int internalKeyBindingId) throws Exception {
        // Ask the key binding to search the database for a new certificate matching its public key
        final String ocspSigningCertificateFingerprint = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(authenticationToken,
                internalKeyBindingId);
        if (!CertTools.getFingerprintAsString(ocspSigningCertificate).equals(ocspSigningCertificateFingerprint)) {
            throw new Error("Wrong certificate was found for InternalKeyBinding");
        }
        OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
    }
    
    /**
     * Build an OCSP request, that will optionally be signed if authentication parameters are specified
     * 
     * @param ocspAuthenticationCertificate signing certificate
     * @param ocspAuthenticationPrivateKey private key to sign with
     * @param caCertificate issuer of the queried certificate
     * @param certificateSerialnumber serial number of the certificate to be queried
     * @return
     * @throws Exception
     */
    private OCSPReq buildOcspRequest(final X509Certificate ocspAuthenticationCertificate, final PrivateKey ocspAuthenticationPrivateKey,
            final X509Certificate caCertificate, final BigInteger certificateSerialnumber) throws Exception {
        final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        if (ocspAuthenticationCertificate != null) {
            // Signed requests are required to have an OCSPRequest.TBSRequest.requestorName
            ocspReqBuilder.setRequestorName(new X500Name(ocspAuthenticationCertificate.getSubjectDN().getName()));
        }
        ocspReqBuilder.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, certificateSerialnumber));
        ocspReqBuilder.setRequestExtensions(new Extensions(new Extension[] {new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()))}));
        if (ocspAuthenticationCertificate != null && ocspAuthenticationPrivateKey != null) {
            // Create a signed request
            final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_SHA1_WITH_RSA).setProvider(
                    BouncyCastleProvider.PROVIDER_NAME).build(ocspAuthenticationPrivateKey), 20480);
            return ocspReqBuilder.build(signer, new X509CertificateHolder[] {new X509CertificateHolder(ocspAuthenticationCertificate.getEncoded())});
        } else {
            // Create an unsigned request
            return ocspReqBuilder.build();
        }
    }
    
    private X509Certificate issueOcspAuthenticationCertificate(final String username, final PublicKey publicKey) throws Exception  {
        return issueOcspAuthenticationCertificate(x509ca.getCAId(), username, publicKey);
    }

    /** Issue a plain end user certificate from the test CA for the provided public key */
    private X509Certificate issueOcspAuthenticationCertificate(final int caid, final String username, final PublicKey publicKey) throws Exception {
        final EndEntityInformation user = new EndEntityInformation(username, "CN="+username, caid, null, null,
                new EndEntityType(EndEntityTypes.ENDUSER), 0, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setStatus(EndEntityConstants.STATUS_NEW);
        user.setPassword("foo123");
        final SimpleRequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword());
        final X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(authenticationToken, user, req,
                org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
        final X509Certificate cert = (X509Certificate)resp.getCertificate();
        assertNotNull("Failed to create certificate", cert);
        assertTrue("Issued certificate was not for the requested public key.", cert.getPublicKey().equals(publicKey));
        return cert;
    }
    
    /** Perform OCSP requests over remote EJB interface and assert the the response is not null. */
    private OCSPResp sendRequest(final OCSPReq ocspRequest) throws MalformedRequestException, IOException, OCSPException {
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction and audit logger for this transaction.
        ConfigurationHolder.updateConfiguration("ocsp.trx-log", "true");
        final TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        final AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        final OcspResponseInformation responseInformation = ocspResponseGeneratorSession.getOcspResponse(ocspRequest.getEncoded(), null, "", null, null,
                auditLogger, transactionLogger);
        byte[] responseBytes = responseInformation.getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);
        return new OCSPResp(responseBytes);
    }
    
    private void validateSuccessfulResponse(final BasicOCSPResp basicOcspResponse, final PublicKey publicKey) throws Exception {
        assertNotNull("Signed request generated null-response.", basicOcspResponse);
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(publicKey)));
        final SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspSigningCertificate.getSerialNumber(), singleResponses[0].getCertID().getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
    }

    /** @return the previous default OCSP responder setting */
    private String setOcspDefaultResponderReference(final String dn) throws AuthorizationDeniedException {
        final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        final String originalDefaultResponder = configuration.getOcspDefaultResponderReference();
        configuration.setOcspDefaultResponderReference(dn);
        globalConfigurationSession.saveConfiguration(authenticationToken, configuration);
        return originalDefaultResponder;
    }
}
