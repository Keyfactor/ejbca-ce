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
package org.cesecore.certificates.ocsp.integrated;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import javax.ejb.EJBException;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.cesecore.CaTestUtils;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
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
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionRemote;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorTestSessionRemote;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 
 * @version $Id$
 * 
 */
public class IntegratedOcspResponseTest extends RoleUsingTestCase {

    private static final String DN = "C=SE,O=Test,CN=TEST";

    
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private OcspResponseGeneratorSessionRemote ocspResponseGeneratorSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspResponseGeneratorSessionRemote.class);
    private OcspResponseGeneratorTestSessionRemote ocspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspResponseGeneratorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    
    private X509Certificate caCertificate;
    private X509Certificate ocspCertificate;
    private int cryptoTokenId;
    private int caId;
    
    private final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal Admin"));

    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
        // Set up base role that can edit roles
        setUpAuthTokenAndRole(this.getClass().getSimpleName());
        // Now we have a role that can edit roles, we can edit this role to include more privileges
        RoleData role = roleAccessSession.findRole(this.getClass().getSimpleName());
        // Add rules to the role
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAADD.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAEDIT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAREMOVE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CREATECERT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), CryptoTokenRules.BASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(internalAdmin, role, accessRules);

        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo123");
        final String className = IntegratedOcspResponseTest.class.getSimpleName();
        final CA testx509ca = CaTestUtils.createX509Ca(internalAdmin, className, className, "CN=TEST,O=Test,C=SE");
        caId = testx509ca.getCAId();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAACCESS.resource() + caId, AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(roleMgmgToken, role, accessRules);

        // Remove any lingering testca before starting the tests
        caSession.removeCA(roleMgmgToken, caId);
        caSession.addCA(roleMgmgToken, testx509ca);
        CAInfo testx509caInfo = caSession.getCAInfo(roleMgmgToken, caId);

        caCertificate = (X509Certificate) testx509caInfo.getCertificateChain().iterator().next();

        // Store a root certificate in the database.
        if (certificateStoreSession.findCertificatesBySubject(DN).isEmpty()) {
            certificateStoreSession.storeCertificate(roleMgmgToken, caCertificate, "foo", "1234", CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ROOTCA, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "footag", new Date().getTime());
        }

        EndEntityInformation user = new EndEntityInformation("username", "CN=User", caId, "rfc822Name=user@user.com",
                "user@user.com", EndEntityTypes.ENDUSER.toEndEntityType(), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setPassword("foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());

        ocspCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                X509ResponseMessage.class)).getCertificate());

        // Modify the default value
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.DEFAULT_RESPONDER, "CN=TEST,O=Test,C=SE");
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.nonexistingisgood", "false");

    }

    @After
    public void tearDown() throws AuthorizationDeniedException, RoleNotFoundException {
        try {
            caSession.removeCA(roleMgmgToken, caId);
            cryptoTokenManagementSession.deleteCryptoToken(roleMgmgToken, cryptoTokenId);
        } finally {
            // Be sure to to this, even if the above fails
            tearDownRemoveRole();
            internalCertificateStoreSession.removeCertificate(caCertificate.getSerialNumber());
            internalCertificateStoreSession.removeCertificate(ocspCertificate.getSerialNumber());
        }
        // Restore the default value
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.defaultresponder", OcspConfiguration.getDefaultResponderId());
    }

    /**
     * Tests creating an OCSP response using the root CA cert.
     */
    @Test
    public void testGetOcspResponseSanity() throws Exception {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, caCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq req = gen.build();
        
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        byte[] responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", "", null, auditLogger, transactionLogger).getOcspResponse();
        assertNotNull("OCSP resonder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", caCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
    }

    @Test
    public void testGetOcspResponseWithOcspCertificate() throws Exception {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        byte[] responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", "", null, auditLogger, transactionLogger).getOcspResponse();
        assertNotNull("OCSP resonder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
    }

    @Test
    public void testGetOcspResponseWithRevokedCertificate() throws Exception {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();

        // Now revoke the ocspCertificate
        certificateStoreSession.setRevokeStatus(roleMgmgToken, ocspCertificate, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, null);
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        byte[] responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", "", null, auditLogger, transactionLogger).getOcspResponse();
        assertNotNull("OCSP resonder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        Object status = singleResponses[0].getCertStatus();
        assertTrue("Status is not RevokedStatus", status instanceof RevokedStatus);
        RevokedStatus rev = (RevokedStatus) status;
        assertTrue("Status does not have reason", rev.hasRevocationReason());
        int reason = rev.getRevocationReason();
        assertEquals("Wrong revocation reason", reason, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
    }

    @Test
    public void testGetOcspResponseWithUnavailableCertificate() throws Exception {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();

        // Now remove the certificate
        internalCertificateStoreSession.removeCertificate(ocspCertificate.getSerialNumber());
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        byte[] responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", "", new StringBuffer("http://foo.com"), auditLogger, transactionLogger).getOcspResponse();
        assertNotNull("OCSP resonder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();

        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());

        // Set that an unknown CA is "good", and redo the test (cache is reloaded automatically)
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.nonexistingisgood", "true");

        responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", "", new StringBuffer("http://foo.com"), auditLogger, transactionLogger).getOcspResponse();
        assertNotNull("OCSP resonder replied null", responseBytes);

        response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        singleResponses = basicOcspResponse.getResponses();

        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());

        // Assert that status is null, i.e. "good"
        assertNull(singleResponses[0].getCertStatus());

        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.nonexistingisgood", "false");
    }

    /**
     * Note that this test is time dependent. Debugging it will create strange behavior.
     * 
     * @throws OCSPException
     * @throws AuthorizationDeniedException
     * @throws MalformedRequestException
     * @throws IOException
     * @throws InterruptedException
     * @throws IllegalCryptoTokenException
     * @throws CADoesntExistsException
     * @throws CertificateEncodingException 
     */
    @Test
    public void testCacheUpdates() throws OCSPException, AuthorizationDeniedException, MalformedRequestException, IOException, InterruptedException,
            CADoesntExistsException, IllegalCryptoTokenException, CertificateEncodingException {
        final Integer timeToWait = 2;
        // Set the validity time to a single second for testing purposes.
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNING_CERTD_VALID_TIME, timeToWait.toString());

        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        try {

            // An OCSP request
            OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspCertificate.getSerialNumber()));
            Extension[] extensions = new Extension[1];
            extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
            gen.setRequestExtensions(new Extensions(extensions));

            OCSPReq req = gen.build();

            byte[] responseBytes;
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
            // Create the transaction logger for this transaction.
            TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
            // Create the audit logger for this transaction.
            AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
            responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", "", null, auditLogger, transactionLogger)
                    .getOcspResponse();
            assertNotNull("OCSP resonder replied null", responseBytes);
            // Initial assert that status is null, i.e. "good"
            assertNull("Test could not run because initial ocsp response failed.",
                    ((BasicOCSPResp) (new OCSPResp(responseBytes)).getResponseObject()).getResponses()[0].getCertStatus());
            // Erase the cert. It should still exist in the cache.
            caSession.removeCA(roleMgmgToken, caId);
            responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", "", null, auditLogger, transactionLogger)
                    .getOcspResponse();
            // Initial assert that status is null, i.e. "good"
            assertNull("Test could not run because cache changed before the entire test could run.",
                    ((BasicOCSPResp) (new OCSPResp(responseBytes)).getResponseObject()).getResponses()[0].getCertStatus());

            // Now sleep and try again, Glassfish has a default "minimum-delivery-interval-in-millis" of 7 seconds, so we have
            // to wait that long, make it 8 seconds. We have set the timer to 2 seconds above.
            Thread.sleep(8 * 1000);

            // Since the CA is gone, expect an exception here.
            try {
                ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", "", null, auditLogger,
                        transactionLogger);
                assertTrue("Should throw OcspException", false);
            } catch (OcspFailureException e) {
                // In JBoss this works, the client actually gets an OcspException
                assertEquals("Unable to find CA certificate and key to generate OCSP response.", e.getMessage());
            } catch (EJBException e) {
                // In glassfish and JBoss 7, a RuntimeException causes an EJBException to be thrown, wrapping the OcspException in many layers...
                Throwable e1 = e.getCausedByException();
                // In JBoss 7 is is wrapped in only one layer
                if (e1 instanceof OcspFailureException) {
                    assertEquals("Unable to find CA certificate and key to generate OCSP response.", e1.getMessage());               
                } else {
                    Throwable e2 = e1.getCause();
                    Throwable e3 = e2.getCause();
                    assertTrue(e3 instanceof OcspFailureException);
                    OcspFailureException e4 = (OcspFailureException) e3;
                    assertEquals("Unable to find CA certificate and key to generate OCSP response.", e4.getMessage());                   
                }
            }

        } finally {
            // Reset sign trust valid time.
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNING_CERTD_VALID_TIME,
                    Integer.toString(OcspConfiguration.getSigningCertsValidTimeInMilliseconds()));

        }
    }

    /**
     * This test should use the default OCSP responder to sign the response as unknown.
     * 
     * @throws OCSPException
     * @throws AuthorizationDeniedException
     * @throws IOException
     * @throws MalformedRequestException
     * @throws CADoesntExistsException
     * @throws IllegalCryptoTokenException
     * @throws NoSuchProviderException
     * @throws CertificateEncodingException 
     * @throws OperatorCreationException 
     */
    @Test
    public void testGetOcspResponseWithCertificateFromUnknownCa() throws OCSPException, AuthorizationDeniedException, IOException,
            MalformedRequestException, CADoesntExistsException, IllegalCryptoTokenException, NoSuchProviderException, CertificateEncodingException, OperatorCreationException {

        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), ocspCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        byte[] responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", "", null, auditLogger, transactionLogger).getOcspResponse();
        assertNotNull("OCSP resonder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();

        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());

        assertTrue(singleResponses[0].getCertStatus() instanceof UnknownStatus);

    }

    @Test
    public void testGetOcspResponseWithIncorrectDefaultResponder() throws OCSPException, AuthorizationDeniedException, IOException,
            MalformedRequestException, CADoesntExistsException, IllegalCryptoTokenException, CertificateEncodingException {
        // Set a fake value
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.DEFAULT_RESPONDER, "CN=FancyPants");

        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), ocspCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();

        // At first try, it should throw an exception because it can not find the default responder
        try {
            final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
            // Create the transaction logger for this transaction.
            TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
            // Create the audit logger for this transaction.
            AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
            ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", "", null, auditLogger,
                    transactionLogger);
            fail("Should throw OcspFailureException");
        } catch (OcspFailureException e) {
            // In JBoss this works, the client actually gets an OcspException
            assertEquals("Unable to find CA certificate and key to generate OCSP response.", e.getMessage());
        } catch (EJBException e) {
            // In glassfish and JBoss 7, a RuntimeException causes an EJBException to be thrown, wrapping the OcspException in many layers...
            Throwable e1 = e.getCausedByException();
            // In JBoss 7 is is wrapped in only one layer
            if (e1 instanceof OcspFailureException) {
                assertEquals("Unable to find CA certificate and key to generate OCSP response.", e1.getMessage());               
            } else {
                Throwable e2 = e1.getCause();
                Throwable e3 = e2.getCause();
                assertTrue(e3 instanceof OcspFailureException);
                OcspFailureException e4 = (OcspFailureException) e3;
                assertEquals("Unable to find CA certificate and key to generate OCSP response.", e4.getMessage());
            }
        }
    }
    
    /**
     * Makes sure that the OcspSigningCache doesn't add Unsigned CAs
     * @throws AuthorizationDeniedException 
     * @throws IllegalCryptoTokenException 
     * @throws CAExistsException 
     * @throws CADoesntExistsException 
     * @throws InvalidAlgorithmException 
     */
    @Test
    public void testOcspSigningCacheDoesntAddUnsignedCa() throws CAExistsException, IllegalCryptoTokenException, AuthorizationDeniedException,
            CADoesntExistsException, InvalidAlgorithmException {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo1234");
        int cryptoTokenId = 0;
        try {
            try {
                cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(internalAdmin, "testOcspSigningCacheDoesntAddUnsignedCa",
                        SoftCryptoToken.class.getName(), cryptoTokenProperties, null, null);
                cryptoTokenManagementSession.createKeyPair(internalAdmin, cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS, "1024");
                cryptoTokenManagementSession.createKeyPair(internalAdmin, cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS, "1024");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            // Create CAToken (what key in the CryptoToken should be used for what)
            final Properties caTokenProperties = new Properties();
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
            final CAToken catoken = new CAToken(cryptoTokenId, caTokenProperties);
            catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
            catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);

            // Create an inactive OSCP CA Service.

            X509CAInfo cainfo = new X509CAInfo("CN=TESTSIGNEDBYEXTERNAL", "TESTSIGNEDBYEXTERNAL", CAConstants.CA_WAITING_CERTIFICATE_RESPONSE, new Date(), "",
                    CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, 1000, null, // Expiretime
                    CAInfo.CATYPE_X509, CAInfo.SIGNEDBYEXTERNALCA, // Signed by the first TEST CA we created
                    (Collection<Certificate>) null, catoken, "TESTSIGNEDBYEXTERNAL", -1, null, null, // PolicyId
                    24 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLPeriod
                    0 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLIssueInterval
                    10 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLOverlapTime
                    10 * SimpleTime.MILLISECONDS_PER_HOUR, // DeltaCRLPeriod
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
                    new ArrayList<ExtendedCAServiceInfo>(), false, // use default utf8 settings
                    new ArrayList<Integer>(), // Approvals Settings
                    1, // Number of Req approvals
                    false, // Use UTF8 subject DN by default
                    true, // Use LDAP DN order by default
                    false, // Use CRL Distribution Point on CRL
                    false, // CRL Distribution Point on CRL critical
                    true, true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    false, // useCertReqHistory
                    true, // useUserStorage
                    true, // useCertificateStorage
                    null // cmpRaAuthSecret
            );
            try {
                CA ca = new X509CA(cainfo);
                ca.setCAToken(catoken);
                ocspResponseGeneratorTestSession.reloadOcspSigningCache();
                int originalCacheSize = ocspResponseGeneratorTestSession.getCacheOcspCertificates().size();
                caSession.addCA(internalAdmin, ca);
                ocspResponseGeneratorTestSession.reloadOcspSigningCache();
                int laterCacheSize = ocspResponseGeneratorTestSession.getCacheOcspCertificates().size();
                assertEquals("An unsigned CA has been added to cache.", originalCacheSize, laterCacheSize);
            } finally {
                caSession.removeCA(internalAdmin, cainfo.getCAId());
            }
        } finally {
            if (cryptoTokenId != 0) {
                cryptoTokenManagementSession.deleteCryptoToken(internalAdmin, cryptoTokenId);
            }
        }
    }

}
