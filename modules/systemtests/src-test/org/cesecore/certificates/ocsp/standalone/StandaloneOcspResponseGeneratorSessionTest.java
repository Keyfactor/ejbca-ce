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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
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
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
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
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
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

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateCreateSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private  final CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
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
        //Make sure default responder is restored
        GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        ocspConfiguration.setOcspDefaultResponderReference(originalDefaultResponder);
        globalConfigurationSession.saveConfiguration(authenticationToken, ocspConfiguration);
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
        certificateStoreSession.setRevokeStatus(authenticationToken, ocspSigningCertificate, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, null);
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
     * Tests the case of a standalone OCSP responder with a revoked certificate issuer.
     * 
     * This should respond revoked, as from the RFC:
     * 
     *  If an OCSP responder knows that a particular CA's private key has
     *  been compromised, it MAY return the revoked state for all
     *  certificates issued by that CA.
     */
    @Test
    public void testResponseWithRevokedResponderIssuer() throws Exception {
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        //Revoke the issuer cert
        certificateStoreSession.setRevokeStatus(authenticationToken, caCertificate, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, null);
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
        
    /** Tests using the default responder for external CAs for a good certificate. */
    @Test
    public void testResponseWithDefaultResponderForExternal() throws Exception {
        // Make sure that a default responder is set
        GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        final String originalDefaultResponder = ocspConfiguration.getOcspDefaultResponderReference();
        ocspConfiguration.setOcspDefaultResponderReference(CertTools.getIssuerDN(ocspSigningCertificate));
        globalConfigurationSession.saveConfiguration(authenticationToken, ocspConfiguration);
        try {
            //Make default responder standalone
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);      
            // Now, construct an external CA. 
            final String externalCaName = "testStandAloneOcspResponseExternalCa";
            final String externalCaSubjectDn = "CN=" + externalCaName;
            long validity = 3650L;
            KeyPair externalCaKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            Certificate externalCaCertificate = CertTools.genSelfCert(externalCaSubjectDn, validity, null, externalCaKeys.getPrivate(),
                    externalCaKeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
            X509CAInfo externalCaInfo = new X509CAInfo(externalCaSubjectDn, externalCaName, CAConstants.CA_EXTERNAL,
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE, validity, CAInfo.SELFSIGNED, null, null);
            CAToken token = new CAToken(externalCaInfo.getCAId(), new NullCryptoToken().getProperties());
            X509CA externalCa = new X509CA(externalCaInfo);
            externalCa.setCAToken(token);
            externalCa.setCertificateChain(Arrays.asList(externalCaCertificate));
            caSession.addCA(authenticationToken, externalCa);
            certificateStoreSession.storeCertificate(authenticationToken, externalCaCertificate, externalCaName, "1234",
                    CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ROOTCA,
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE, null, new Date().getTime());
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
                final SubjectPublicKeyInfo pkinfo = new SubjectPublicKeyInfo((ASN1Sequence) ASN1Primitive.fromByteArray(certificateKeyPair
                        .getPublic().getEncoded()));
                X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name(externalCaSubjectDn, false),
                        new BigInteger(serno).abs(), firstDate, lastDate, CertTools.stringToBcX500Name(externalSubjectDn, false), pkinfo);
                final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder("SHA256WithRSA").setProvider(
                        BouncyCastleProvider.PROVIDER_NAME).build(externalCaKeys.getPrivate()), 20480);
                final X509CertificateHolder certHolder = certbuilder.build(signer);
                X509Certificate importedCertificate = (X509Certificate) CertTools.getCertfromByteArray(certHolder.getEncoded());
                certificateStoreSession.storeCertificate(authenticationToken, importedCertificate, externalUsername, "1234",
                        CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY,
                        CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, new Date().getTime());
                try {
                    //Now everything is in place. Perform a request, make sure that the default responder signed it. 
                    final OCSPReq ocspRequest = buildOcspRequest(null, null, (X509Certificate) externalCaCertificate,
                            importedCertificate.getSerialNumber());
                    final OCSPResp response = sendRequest(ocspRequest);
                    assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
                    final BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
                    assertNotNull("Signed request generated null-response.", basicOcspResponse);
                    assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(ocspSigningCertificate.getPublicKey())));
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
        } finally {
            GlobalOcspConfiguration restoredOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            ocspConfiguration.setOcspDefaultResponderReference(originalDefaultResponder);
            globalConfigurationSession.saveConfiguration(authenticationToken, restoredOcspConfiguration);
        }
    }
    
    /** Tests using the default responder for external CAs for a good certificate. */
    @Test
    public void testResponseWithDefaultResponderForExternalNoDefaultSet() throws Exception {
        // Make sure that a default responder is set
        GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        ocspConfiguration.setOcspDefaultResponderReference("");
        globalConfigurationSession.saveConfiguration(authenticationToken, ocspConfiguration);
        String originalNoneExistingIsGood = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.NONE_EXISTING_IS_GOOD);
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NONE_EXISTING_IS_GOOD, "false");
        try {
            //Make default responder standalone
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);      
            // Now, construct an external CA. 
            final String externalCaName = "testStandAloneOcspResponseExternalCa";
            final String externalCaSubjectDn = "CN=" + externalCaName;
            long validity = 3650L;
            KeyPair externalCaKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            Certificate externalCaCertificate = CertTools.genSelfCert(externalCaSubjectDn, validity, null, externalCaKeys.getPrivate(),
                    externalCaKeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
            X509CAInfo externalCaInfo = new X509CAInfo(externalCaSubjectDn, externalCaName, CAConstants.CA_EXTERNAL,
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE, validity, CAInfo.SELFSIGNED, null, null);
            CAToken token = new CAToken(externalCaInfo.getCAId(), new NullCryptoToken().getProperties());
            X509CA externalCa = new X509CA(externalCaInfo);
            externalCa.setCAToken(token);
            externalCa.setCertificateChain(Arrays.asList(externalCaCertificate));
            caSession.addCA(authenticationToken, externalCa);
            certificateStoreSession.storeCertificate(authenticationToken, externalCaCertificate, externalCaName, "1234",
                    CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ROOTCA,
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE, null, new Date().getTime());
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
                final SubjectPublicKeyInfo pkinfo = new SubjectPublicKeyInfo((ASN1Sequence) ASN1Primitive.fromByteArray(certificateKeyPair
                        .getPublic().getEncoded()));
                X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name(externalCaSubjectDn, false),
                        new BigInteger(serno).abs(), firstDate, lastDate, CertTools.stringToBcX500Name(externalSubjectDn, false), pkinfo);
                final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder("SHA256WithRSA").setProvider(
                        BouncyCastleProvider.PROVIDER_NAME).build(externalCaKeys.getPrivate()), 20480);
                final X509CertificateHolder certHolder = certbuilder.build(signer);
                X509Certificate importedCertificate = (X509Certificate) CertTools.getCertfromByteArray(certHolder.getEncoded());
                certificateStoreSession.storeCertificate(authenticationToken, importedCertificate, externalUsername, "1234",
                        CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY,
                        CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, new Date().getTime());
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
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NONE_EXISTING_IS_GOOD, originalNoneExistingIsGood);
        }
    }
    
    /** Tests using the default responder for external CAs, tests with a revoked cert */
    @Test
    public void testResponseWithDefaultResponderForExternalRevoked() throws Exception {
        // Make sure that a default responder is set
        GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        ocspConfiguration.setOcspDefaultResponderReference(CertTools.getIssuerDN(ocspSigningCertificate));
        globalConfigurationSession.saveConfiguration(authenticationToken, ocspConfiguration);
        String originalNoneExistingIsGood = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.NONE_EXISTING_IS_GOOD);
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NONE_EXISTING_IS_GOOD, "false");
        try {
            //Make default responder standalone
            OcspTestUtils.deleteCa(authenticationToken, x509ca);
            activateKeyBinding(internalKeyBindingId);      
            // Now, construct an external CA. 
            final String externalCaName = "testStandAloneOcspResponseExternalCa";
            final String externalCaSubjectDn = "CN=" + externalCaName;
            long validity = 3650L;
            KeyPair externalCaKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            Certificate externalCaCertificate = CertTools.genSelfCert(externalCaSubjectDn, validity, null, externalCaKeys.getPrivate(),
                    externalCaKeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
            X509CAInfo externalCaInfo = new X509CAInfo(externalCaSubjectDn, externalCaName, CAConstants.CA_EXTERNAL,
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE, validity, CAInfo.SELFSIGNED, null, null);
            CAToken token = new CAToken(externalCaInfo.getCAId(), new NullCryptoToken().getProperties());
            X509CA externalCa = new X509CA(externalCaInfo);
            externalCa.setCAToken(token);
            externalCa.setCertificateChain(Arrays.asList(externalCaCertificate));
            caSession.addCA(authenticationToken, externalCa);
            certificateStoreSession.storeCertificate(authenticationToken, externalCaCertificate, externalCaName, "1234",
                    CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ROOTCA,
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE, null, new Date().getTime());
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
                final SubjectPublicKeyInfo pkinfo = new SubjectPublicKeyInfo((ASN1Sequence) ASN1Primitive.fromByteArray(certificateKeyPair
                        .getPublic().getEncoded()));
                X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name(externalCaSubjectDn, false),
                        new BigInteger(serno).abs(), firstDate, lastDate, CertTools.stringToBcX500Name(externalSubjectDn, false), pkinfo);
                final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder("SHA256WithRSA").setProvider(
                        BouncyCastleProvider.PROVIDER_NAME).build(externalCaKeys.getPrivate()), 20480);
                final X509CertificateHolder certHolder = certbuilder.build(signer);
                X509Certificate importedCertificate = (X509Certificate) CertTools.getCertfromByteArray(certHolder.getEncoded());
                certificateStoreSession.storeCertificate(authenticationToken, importedCertificate, externalUsername, "1234",
                        CertificateConstants.CERT_REVOKED, CertificateConstants.CERTTYPE_ENDENTITY,
                        CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, new Date().getTime());
                try {
                    //Now everything is in place. Perform a request, make sure that the default responder signed it. 
                    final OCSPReq ocspRequest = buildOcspRequest(null, null, (X509Certificate) externalCaCertificate,
                            importedCertificate.getSerialNumber());
                    final OCSPResp response = sendRequest(ocspRequest);
                    assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
                    final BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
                    assertNotNull("Signed request generated null-response.", basicOcspResponse);
                    assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(ocspSigningCertificate.getPublicKey())));
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
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NONE_EXISTING_IS_GOOD, originalNoneExistingIsGood);
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
        GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        ocspConfiguration.setOcspDefaultResponderReference(CertTools.getIssuerDN(ocspSigningCertificate));
        globalConfigurationSession.saveConfiguration(authenticationToken, ocspConfiguration);
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
                    basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(ocspSigningCertificate.getPublicKey())));
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
        assertNull("We expected the response object to be null when 'Signature Required' is recieved.", ocspResponseUnsigned.getResponseObject());
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
        certificateStoreSession.storeCertificate(authenticationToken, signerIssuerCaCertificate, "foo", "1234", CertificateConstants.CERT_ACTIVE,
                CertificateConstants.CERTTYPE_ROOTCA, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "footag", new Date().getTime());
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
                certificateStoreSession.setRevokeStatus(authenticationToken, ocspAuthenticationCertificate,
                        RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, null);
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
        GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        ocspConfiguration.setOcspDefaultResponderReference("CN=FancyPants");
        globalConfigurationSession.saveConfiguration(authenticationToken, ocspConfiguration);
        
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
            byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, auditLogger, transactionLogger)
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
        final OcspResponseInformation responseInformation = ocspResponseGeneratorSession.getOcspResponse(ocspRequest.getEncoded(), null, "", null,
                auditLogger, transactionLogger);
        byte[] responseBytes = responseInformation.getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);
        return new OCSPResp(responseBytes);
    }
    
    private void validateSuccessfulResponse(final BasicOCSPResp basicOcspResponse, final PublicKey publicKey) throws Exception {
        assertNotNull("Signed request generated null-response.", basicOcspResponse);
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(publicKey)));
        final SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspSigningCertificate.getSerialNumber(), singleResponses[0].getCertID().getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
    }
    
}
