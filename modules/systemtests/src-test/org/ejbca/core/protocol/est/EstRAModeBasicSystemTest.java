/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.est;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.string.StringConfigurationCache;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.CaTestUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.junit.util.TraceLogMethodsTestWatcher;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.EstConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.UsernameGenerateMode;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

/**
 * Tests basic EST RA mode. Initial enrollment and re-enrollment with non-registered end entities using RA password, or client certificate for
 * authentication of the CA.
 * Including basic error cases: malicious request (too large), invalid CSR encoding, wrong RA password or lack of access rights for RA certificate.
 */
public class EstRAModeBasicSystemTest extends EstTestCase {

    private static final Logger log = Logger.getLogger(EstRAModeBasicSystemTest.class);

    private static final String TESTCA_NAME = EstRAModeBasicSystemTest.class.getSimpleName();
    protected static final String EEP_NAME_FOR_SAN_TEST = "EST_TEST_EEP_NAME_FOR_SAN";

    private static boolean isESTEnabled = false; // if EST was enabled or not before running test

    private static final GlobalConfigurationSession globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static KeyPair ec256;
    private static KeyPair mldsa44;
    private static KeyPair slhdsa;
    private static String estAlias = "EstRAModeBasicSystemTest";

    int eepIdForSanTest;

    @Rule
    public TestName testName = new TestName();

    @Rule
    public final TestWatcher traceLogMethodsRule = new TraceLogMethodsTestWatcher(log);

    @BeforeClass
    public static void beforeClass() throws CADoesntExistsException, CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, AuthorizationDeniedException, InvalidAlgorithmParameterException {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        CryptoProviderTools.installBCProvider();
        createTestCA(TESTCA_NAME); // Create test CA

        // Enable EST. EstAliasSystemTest tests responses when disabled so here we only want to test enabled functionality
        AvailableProtocolsConfiguration protConf = ((AvailableProtocolsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID));
        isESTEnabled = protConf.getProtocolStatus("EST");
        if (!isESTEnabled) {
            // Enable if not enabled
            protConf.setProtocolStatus("EST", true);
            globalConfigurationSession.saveConfiguration(ADMIN, protConf);
        }
        ec256 = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
        mldsa44 = KeyTools.genKeys("ML-DSA-44", AlgorithmConstants.KEYALGORITHM_MLDSA44);
        slhdsa = KeyTools.genKeys("SLH-DSA-SHA2-128F", AlgorithmConstants.KEYALGORITHM_SLHDSA_SHA2_128F);

        StringConfigurationCache.INSTANCE.setEncryptionKey("qhrnf.f8743;12%#75".toCharArray());

    }

    @AfterClass
    public static void afterClass() throws AuthorizationDeniedException {
        // Set back enablement to what it was before running tests
        AvailableProtocolsConfiguration protConf = ((AvailableProtocolsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID));
        protConf.setProtocolStatus("EST", isESTEnabled);
        try {
            globalConfigurationSession.saveConfiguration(ADMIN, protConf);
        } catch (AuthorizationDeniedException e) {
            log.error(e.getMessage(), e);
        }
        try {
            removeTestCA(TESTCA_NAME);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        // Create a basic EST alias configuration, which is the same for all tests, apart from minor modification we do in each test
        final EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        config.addAlias(estAlias);
        config.setOperationMode(estAlias, EstConfiguration.OPERATION_MODE_RA); // RA mode
        config.setDefaultCAID(estAlias, getTestCAId(TESTCA_NAME));
        config.setEndEntityProfileID(estAlias, eepId);
        config.setCertProfileID(estAlias, cpId);
        // Generate password using the CN from the request subject DN as end entity username
        config.setRANameGenScheme(estAlias, UsernameGenerateMode.DN.name());
        config.setRANameGenParams(estAlias, "CN");
        // Don't allow renewal with same user public key
        config.setKurAllowSameKey(estAlias, false);
        config.setServerKeyGenerationEnabled(estAlias, true);
        globalConfigurationSession.saveConfiguration(ADMIN, config);

        if ("testRASimpleenrollWithSans".equals(testName.getMethodName())) {
            this.eepIdForSanTest = addEndEntityProfile(EEP_NAME_FOR_SAN_TEST, this.cpId, false);
            final EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile(EEP_NAME_FOR_SAN_TEST);
            final int testCaId = getTestCAId(TESTCA_NAME);
            eep.setDefaultCertificateProfile(cpId);
            eep.setAvailableCertificateProfileIds(List.of(cpId));
            eep.setDefaultCA(testCaId);
            eep.setAvailableCAs(List.of(testCaId));
            endEntityProfileSession.changeEndEntityProfile(ADMIN, EEP_NAME_FOR_SAN_TEST, eep);
        }
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        // Remove EST alias
        final EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        config.removeAlias(estAlias);
        globalConfigurationSession.saveConfiguration(ADMIN, config);

        if ("testRASimpleenrollWithSans".equals(testName.getMethodName())) {
            endEntityProfileSession.removeEndEntityProfile(ADMIN, EEP_NAME_FOR_SAN_TEST);
        }
    }

    /**
     * Tests getting CA certificates, when CA exists and when not. {@link EstAliasSystemTest )} already tests cacerts for non existing aliases.
     */
    @Test
    public void testGetCACerts() throws Exception {
        try {
            // Make EST cacerts request here
            byte[] resp = sendEstRequest(estAlias, "cacerts", null, 200, null);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.1.3
            assertNotNull("There must be response data to cacerts request", resp);
            final CMSSignedData msg = new CMSSignedData(Base64.decode(resp));
            final Store<X509CertificateHolder> certstore = msg.getCertificates();
            final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
            assertEquals("EST test CA has a single CA certificate", 1, certs.size());
            final X509Certificate testcacert = (X509Certificate) getTestCACert(TESTCA_NAME);
            assertEquals("cacerts response subjectDN must be our EST test CAs subjectDN", testcacert.getSubjectX500Principal().getName(), certs.iterator().next().getSubject().toString());
        } finally {
        }
    }

    /**
     * Tests RA enrollment using password authentication including testing wrong password and using password when certificate is required.
     */
    @Test
    public void testRASimpleenrollPasswordAuth() throws Exception {
        final String pwd = genRandomPwd();
        final String username = "testRAPasswordAuth" + genRandomUserName();
        try {
            EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            // Authentication using username
            config.setCert(estAlias, false);
            config.setUsername(estAlias, username);
            config.setPassword(estAlias, pwd);
            // Test case with invalid CA
            config.setDefaultCAID(estAlias, getTestCAId(TESTCA_NAME));
            globalConfigurationSession.saveConfiguration(ADMIN, config);

            //
            // 1. Make EST simpleenroll request, message is a simple PKCS#10 request, RFC7030 section 4.2.1
            //
            String requestDN = "CN=" + username + ",O=EJBCA,C=SE";
            PKCS10CertificationRequest p10 = generateCertReq(requestDN, null, null, null, null, ec256, "SHA256WithECDSA");
            byte[] reqmsg = Base64.encode(p10.getEncoded());
            // Send request first without username, should give unauthorized
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 401, "<html><head><title>Error</title></head><body>Invalid username or password</body></html>");
            // Send request without password, should give unauthorized
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 401, "<html><head><title>Error</title></head><body>Invalid username or password</body></html>", username, null);
            // Send request with wrong password, should give unauthorized
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 401, "<html><head><title>Error</title></head><body>Invalid username or password</body></html>", username, "foo123");
            // Send request with correct username and password, but alias requiring certificate, should give unauthorized
            config.setCert(estAlias, true);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 401, "<html><head><title>Error</title></head><body>No client certificate supplied</body></html>", username, pwd);

            // Send request with correct username and password, but alias configured with an invalid CA, should not work
            config.setCert(estAlias, false);
            config.setDefaultCAID(estAlias, 123);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>The requested CA for EST alias 'EstRAModeBasicSystemTest' could not be found: 123</body></html>", username, pwd);

            // Send request with correct username and password, should work
            config.setDefaultCAID(estAlias, getTestCAId(TESTCA_NAME));
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            byte[] resp = sendEstRequest(estAlias, "simpleenroll", reqmsg, 200, null, username, pwd);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            final X509Certificate testcacert = (X509Certificate) getTestCACert(TESTCA_NAME);
            X509Certificate cert = getCertFromResponse(resp);
            assertSimpleEnrollResponse(requestDN, resp, ec256, testcacert);

            final CAInfo serverCertCaInfo = CaTestUtils.getServerCertCaInfo(ADMIN);
            config.setDefaultCAID(estAlias, serverCertCaInfo.getCAId());
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // use simpleenroll to create a cert with same keypair from csr
            requestDN = "CN=" + username + "_second,O=EJBCA,C=SE";
            p10 = generateCertReq(requestDN, null, null, null, null, ec256, "SHA256WithECDSA");
            reqmsg = Base64.encode(p10.getEncoded());

            resp = sendEstRequest(estAlias, "simpleenroll", reqmsg, 200, null, username, pwd);
            X509Certificate tlsReenrollCert = getCertFromResponse(resp);

            resp = sendEstRequest(estAlias, "serverkeygen", reqmsg, 200, null, username, pwd);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            assertKeyGenResponse(requestDN, resp, ec256);
            cert = getCertFromKeygenResponse(resp);

            // subsequent key generation
            final KeyPair ec256New = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
            final PKCS10CertificationRequest p10New = generateCertReq(requestDN, null, null, null, null, ec256New, "SHA256WithECDSA");
            final byte[] reqmsgNew = Base64.encode(p10New.getEncoded());
            X509Certificate oldCert = cert;

            setupClientKeyStore(serverCertCaInfo, ec256, tlsReenrollCert);
            resp = sendEstRequest(true, estAlias, "serverkeygen", reqmsgNew, 200, null, null, null);
            cert = getCertFromKeygenResponse(resp);

            assertKeyGenResponse(requestDN, resp, ec256New);
            assertNotEquals("serverkeygen response public key must be the differant than the old key", Base64.toBase64String(oldCert.getPublicKey().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));
        } finally {
            // Remove the generated end entity and all the certificates
            internalCertStoreSession.removeCertificatesByUsername(username);
            try {
                endEntityManagementSession.deleteUser(ADMIN, username);
            } catch (NoSuchEndEntityException e) {
            } // NOPMD
        }
    }

    /**
     * Tests RA enrollment using certificate authentication including testing wrong password and using password when certificate is required.
     */
    @Test
    public void testRASimpleenrollCertAuth() throws Exception {
        final String pwd = genRandomPwd();
        final String adminUsername = "testRACertAuthAdmin" + genRandomUserName();
        final String clientUsername = "testRACertAuthClient" + genRandomUserName();
        RoleMember member = null;
        try {
            final EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            // Admin cert needs a certificate issued by ManagementCA in order to make TLS client cert requests
            final CAInfo serverCertCaInfo = CaTestUtils.getServerCertCaInfo(ADMIN);
            config.setDefaultCAID(estAlias, serverCertCaInfo.getCAId());
            // Authentication using username
            config.setCert(estAlias, false);
            config.setUsername(estAlias, adminUsername);
            config.setPassword(estAlias, pwd);
            globalConfigurationSession.saveConfiguration(ADMIN, config);

            //
            // 1. Issue a first certificate for outr Admin with a EST simpleenroll request, message is a simple PKCS#10 request, RFC7030 section 4.2.1
            //
            final KeyPair ec256Admin = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
            final String adminRequestDN = "CN=" + adminUsername + ",O=EJBCA,C=SE";
            final PKCS10CertificationRequest p10Admin = generateCertReq(adminRequestDN, null, null, null, null, ec256Admin, "SHA256WithECDSA");
            byte[] reqmsgAdmin = Base64.encode(p10Admin.getEncoded());
            byte[] respAdmin = sendEstRequest(estAlias, "simpleenroll", reqmsgAdmin, 200, null, adminUsername, pwd);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3 (tests on this is made in enroll test method)
            assertNotNull("There must be response data to simpleenroll request", respAdmin);
            CMSSignedData respmsg = new CMSSignedData(Base64.decode(respAdmin));
            Collection<X509CertificateHolder> certs = respmsg.getCertificates().getMatches(null);
            // This is our client certificate for re-enrollment
            X509Certificate cert = CertTools.getCertfromByteArray(certs.iterator().next().getEncoded(), X509Certificate.class);
            // Make all requests with client cert auth
            setupClientKeyStore(serverCertCaInfo, ec256Admin, cert);

            //
            // 2. Make EST simpleenroll request with client cert authentication, message is a simple PKCS#10 request, RFC7030 section 4.2.1
            //
            final String requestDN = "CN=" + clientUsername + ",O=EJBCA,C=SE";
            PKCS10CertificationRequest p10 = generateCertReq(requestDN, null, null, null, null, ec256, "SHA256WithECDSA");
            byte[] reqmsg = Base64.encode(p10.getEncoded());
            // Send request first client cert auth, but no username, should give unauthorized
            sendEstRequest(true, estAlias, "simpleenroll", reqmsg, 401, "<html><head><title>Error</title></head><body>Invalid username or password</body></html>", null, null);
            // Require certificate now
            config.setCert(estAlias, true);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // Send request now first client cert auth, but no username, should give unauthorized, since our cert is not authorized in any role
            // A bit different depending on if we send username or not, but all cases should fail
            sendEstRequest(true, estAlias, "simpleenroll", reqmsg, 401, "<html><head><title>Error</title></head><body>Invalid username or password</body></html>", null, null);
            final String msg = "Administrator '" + adminRequestDN + "' not authorized to CA " + serverCertCaInfo.getCAId() + ".";
            sendEstRequest(true, estAlias, "simpleenroll", reqmsg, 403, "<html><head><title>Error</title></head><body>" + msg + "</body></html>", adminUsername, pwd);
            // If we remove username possibility we will always get cet auth failure
            config.setUsername(estAlias, null);
            config.setPassword(estAlias, null);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            sendEstRequest(true, estAlias, "simpleenroll", reqmsg, 403, "<html><head><title>Error</title></head><body>" + msg + "</body></html>", null, null);

            // Authorize our admin cert to a role, after that we should be able to enroll nicely
            member = addToSuperAdminRole(serverCertCaInfo.getCAId(), adminUsername);
            byte[] resp = sendEstRequest(true, estAlias, "simpleenroll", reqmsg, 200, null, null, null);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            respmsg = new CMSSignedData(Base64.decode(resp));
            certs = respmsg.getCertificates().getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, certs.size());
            final X509Certificate testcacert = (X509Certificate) serverCertCaInfo.getCertificateChain().get(0);
            cert = CertTools.getCertfromByteArray(certs.iterator().next().getEncoded(), X509Certificate.class);
            assertSimpleEnrollResponse(requestDN, resp, ec256, testcacert);

            resp = sendEstRequest(true, estAlias, "serverkeygen", reqmsg, 200, null, null, null);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertKeyGenResponse(requestDN, resp, ec256);
        } finally {
            // Remove from super admin role
            if (member != null) {
                removeFromSuperAdminRole(member.getId());
            }
            // Remove the generated end entity and all the certificates
            internalCertStoreSession.removeCertificatesByUsername(clientUsername);
            try {
                endEntityManagementSession.deleteUser(ADMIN, clientUsername);
            } catch (NoSuchEndEntityException e) {
            } // NOPMD
            internalCertStoreSession.removeCertificatesByUsername(adminUsername);
            try {
                endEntityManagementSession.deleteUser(ADMIN, adminUsername);
            } catch (NoSuchEndEntityException e) {
            } // NOPMD
        }
    }

    /**
     * Tests re-enrollment with EST alias in RA mode including wrong enrolment with missmatch between TLS cert and CSR as well as revoked TLS cert.
     */
    @Test
    public void testRASimpleReenroll() throws Exception {
        final String pwd = genRandomPwd();
        final String username = "ESTRAReenroll" + genRandomUserName();
        try {
            final EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            // In order to re-enroll we need to be able to establish a TLS connection with client authentication, which means
            // that we need a client certificate issued from ManagementCA, which is an accepted CA for TLS client certs
            // We also need to enroll against port 8443
            // Apart from that we use the same EST alias as for enrollment test
            // Trusted CA setup: import CA that issued server certificate into trustedKeyStore (configurable with target.servercert.ca)
            final CAInfo serverCertCaInfo = CaTestUtils.getServerCertCaInfo(ADMIN);
            config.setDefaultCAID(estAlias, serverCertCaInfo.getCAId());
            // Authentication using username
            config.setCert(estAlias, false);
            config.setUsername(estAlias, username);
            config.setPassword(estAlias, pwd);
            globalConfigurationSession.saveConfiguration(ADMIN, config);

            //
            // 1. Issue a first certificate with a EST simpleenroll request, message is a simple PKCS#10 request, RFC7030 section 4.2.1
            //
            final String requestDN = "CN=" + username + ",O=EJBCA,C=SE";
            final PKCS10CertificationRequest p10 = generateCertReq(requestDN, null, null, null, null, ec256, "SHA256WithECDSA");
            final byte[] reqmsg = Base64.encode(p10.getEncoded());
            byte[] resp = sendEstRequest(estAlias, "simpleenroll", reqmsg, 200, null, username, pwd);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3 (tests on this is made in enroll test method)
            assertNotNull("There must be response data to simpleenroll request", resp);
            CMSSignedData respmsg = new CMSSignedData(Base64.decode(resp));
            Collection<X509CertificateHolder> certs = respmsg.getCertificates().getMatches(null);
            // This is our client certificate for re-enrollment
            X509Certificate cert = CertTools.getCertfromByteArray(certs.iterator().next().getEncoded(), X509Certificate.class);

            //
            // 2. Make EST simplereenroll request, message is a simple PKCS#10 request, RFC7030 section 4.2.2
            //
            // No client certificate should give unauthorized, regardless if we have username/pwd or not
            sendEstRequest(estAlias, "simplereenroll", reqmsg, 401, "<html><head><title>Error</title></head><body>Can't reenroll without using a TLS client cert</body></html>",
                    username, pwd);
            sendEstRequest(estAlias, "simplereenroll", reqmsg, 401, "<html><head><title>Error</title></head><body>Can't reenroll without using a TLS client cert</body></html>",
                    null, null);
            // Now try with actual client cert authentication, using a certificate that can be used for client cert auth, i.e. Management CA as we got above
            setupClientKeyStore(serverCertCaInfo, ec256, cert);
            // Not allowing same keys should give an error, this gives today 400 (SC_BAD_REQUEST) but should probably be a 401 instead
            // Log will show: 2021-02-22 11:03:07,822 INFO  [org.ejbca.core.protocol.est.EstOperationsSessionBean] (default task-4) Invalid key. The public key in the KeyUpdateRequest is the same as the public key in the existing end entity certificate: CN=ESTRARAReenroll036018,O=EJBCA,C=SE
            sendEstRequest(true, estAlias, "simplereenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Exception encountered when performing EST operation 'simplereenroll' on alias 'EstRAModeBasicSystemTest'.</body></html>",
                    null, null);
            // A new request with new keys, but with the same subject DN should succeed
            final KeyPair ec256New = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
            final PKCS10CertificationRequest p10New = generateCertReq(requestDN, null, null, null, null, ec256New, "SHA256WithECDSA");
            final byte[] reqmsgNew = Base64.encode(p10New.getEncoded());
            resp = sendEstRequest(true, estAlias, "simplereenroll", reqmsgNew, 200, null, null, null);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            respmsg = new CMSSignedData(Base64.decode(resp));
            certs = respmsg.getCertificates().getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, certs.size());
            final X509Certificate testcacert = (X509Certificate) serverCertCaInfo.getCertificateChain().get(0);
            cert = CertTools.getCertfromByteArray(certs.iterator().next().getEncoded(), X509Certificate.class);
            assertSimpleEnrollResponse(requestDN, resp, ec256New, testcacert);

            // Checking for enrollment with the same public key only compares the TLS cert (reenroll authentication) with the CSR, it does not loop through all existing client certificates
            // so a failed reenroll can be retried with the same CSR, therefore it should work to reenroll with the same (new) CSR as long as we use the old key for TLS authentication
            resp = sendEstRequest(true, estAlias, "simplereenroll", reqmsgNew, 200, null, null, null);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);

            // Try again, but now using the new key for TLS authentication as well, not allowing same keys should give an error as above with the new request as well
            setupClientKeyStore(serverCertCaInfo, ec256New, cert);
            sendEstRequest(true, estAlias, "simplereenroll", reqmsgNew, 400, "<html><head><title>Error</title></head><body>Exception encountered when performing EST operation 'simplereenroll' on alias 'EstRAModeBasicSystemTest'.</body></html>",
                    null, null);
            // Modify alias to allow same keys
            config.setKurAllowSameKey(estAlias, true);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            resp = sendEstRequest(true, estAlias, "simplereenroll", reqmsgNew, 200, null, null, null);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            respmsg = new CMSSignedData(Base64.decode(resp));
            certs = respmsg.getCertificates().getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, certs.size());

            // Change the subject DN in the CSR, should not be allowed to reenroll now
            // Log will show: 11:11:45,539 INFO  [org.ejbca.core.protocol.est.EstOperationsSessionBean] (default task-4) Can't reenroll using different subject than requesting certificate. Request DN='CN=ESTRARAReenroll204554,OU=Test,O=EJBCA,C=SE'
            final PKCS10CertificationRequest p10NewDN = generateCertReq(requestDN + ",OU=Test", null, null, null, null, ec256New, "SHA256WithECDSA");
            final byte[] reqmsgNewDN = Base64.encode(p10NewDN.getEncoded());
            sendEstRequest(true, estAlias, "simplereenroll", reqmsgNewDN, 400, "<html><head><title>Error</title></head><body>Exception encountered when performing EST operation 'simplereenroll' on alias 'EstRAModeBasicSystemTest'.</body></html>",
                    null, null);
        } finally {
            // Remove the generated end entity and all the certificates
            internalCertStoreSession.removeCertificatesByUsername(username);
            try {
                endEntityManagementSession.deleteUser(ADMIN, username);
            } catch (NoSuchEndEntityException e) {
            } // NOPMD
        }
    }

    /**
     * Tests RA enrollment using ML-DSA-44 algorithm and password authentication including testing wrong password and using password when certificate is required.
     */
    @Test
    public void testRASimpleenrollPasswordAuthUsingMlDsa44() throws Exception {
        final String pwd = genRandomPwd();
        final String username = "testRAPasswordAuthUsingMlDsa44" + genRandomUserName();
        try {
            EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            // Authentication using username
            config.setCert(estAlias, false);
            config.setUsername(estAlias, username);
            config.setPassword(estAlias, pwd);
            // Test case with invalid CA
            config.setDefaultCAID(estAlias, getTestCAId(TESTCA_NAME));
            globalConfigurationSession.saveConfiguration(ADMIN, config);

            //
            // 1. Make EST simpleenroll request, message is a simple PKCS#10 request, RFC7030 section 4.2.1
            //
            String requestDN = "CN=" + username + ",O=EJBCA,C=SE";
            PKCS10CertificationRequest p10 = generateCertReq(requestDN, null, null, null, null, mldsa44, "ML-DSA-44");
            byte[] reqmsg = Base64.encode(p10.getEncoded());
            // Send request first without username, should give unauthorized
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 401,
                    "<html><head><title>Error</title></head><body>Invalid username or password</body></html>");
            // Send request without password, should give unauthorized
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 401,
                    "<html><head><title>Error</title></head><body>Invalid username or password</body></html>", username, null);
            // Send request with wrong password, should give unauthorized
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 401,
                    "<html><head><title>Error</title></head><body>Invalid username or password</body></html>", username, "foo123");
            // Send request with correct username and password, but alias requiring certificate, should give unauthorized
            config.setCert(estAlias, true);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 401,
                    "<html><head><title>Error</title></head><body>No client certificate supplied</body></html>", username, pwd);

            // Send request with correct username and password, but alias configured with an invalid CA, should not work
            config.setCert(estAlias, false);
            config.setDefaultCAID(estAlias, 123);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 400,
                    "<html><head><title>Error</title></head><body>The requested CA for EST alias 'EstRAModeBasicSystemTest' could not be found: 123</body></html>",
                    username, pwd);

            // Send request with correct username and password, should work
            config.setDefaultCAID(estAlias, getTestCAId(TESTCA_NAME));
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            byte[] resp = sendEstRequest(estAlias, "simpleenroll", reqmsg, 200, null, username, pwd);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertSimpleEnrollResponse(requestDN, resp, mldsa44, (X509Certificate) getTestCACert(TESTCA_NAME));

            final CAInfo serverCertCaInfo = CaTestUtils.getServerCertCaInfo(ADMIN);
            config.setDefaultCAID(estAlias, serverCertCaInfo.getCAId());
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // use simpleenroll to create a cert with same keypair from csr
            requestDN = "CN=" + username + "_second,O=EJBCA,C=SE";
            p10 = generateCertReq(requestDN, null, null, null, null, mldsa44, "ML-DSA-44");
            reqmsg = Base64.encode(p10.getEncoded());

            resp = sendEstRequest(estAlias, "simpleenroll", reqmsg, 200, null, username, pwd);
            X509Certificate tlsReenrollCert = getCertFromResponse(resp);

            resp = sendEstRequest(estAlias, "serverkeygen", reqmsg, 200, null, username, pwd);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertKeyGenResponse(requestDN, resp, mldsa44);

            // subsequent key generation
            /* rest of the statement is not working as wildfly does not support ML-DSA-44
            final KeyPair mldsa44New = KeyTools.genKeys("ML-DSA-44", AlgorithmConstants.KEYALGORITHM_MLDSA44);
            final PKCS10CertificationRequest p10New = generateCertReq(requestDN, null, null, null, null, mldsa44New, "ML-DSA-44");
            final byte[] reqmsgNew = Base64.encode(p10New.getEncoded());
            X509Certificate oldCert = cert;

            setupClientKeyStore(serverCertCaInfo, mldsa44, tlsReenrollCert);
            resp = sendEstRequest(true, estAlias, "serverkeygen", reqmsgNew, 200, null, null, null);
            assertNotNull("There must be response data to simpleenroll request", resp);
            cert = getCertFromKeygenResponse(resp);
            assertEquals("serverkeygen response issuerDN must be our EST test CAs subjectDN", serverCertCaInfo.getSubjectDN(), CertTools.getIssuerDN(cert));
            try {
                cert.verify(serverCertCaInfo.getCertificateChain().get(0).getPublicKey());
            } catch (SignatureException e) {
                fail("serverkeygen response certifciate must verify with CA certificate");
            }
            assertEquals("serverkeygen response subjectDN must be our PKCS#10 request DN", requestDN, cert.getSubjectDN().toString());
            assertNotEquals("serverkeygen response public key must be the differant than the PKCS#10 request", Base64.toBase64String(mldsa44New.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));
            assertNotEquals("serverkeygen response public key must be the differant than the old key", Base64.toBase64String(oldCert.getPublicKey().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));
            */

        } finally {
            // Remove the generated end entity and all the certificates
            internalCertStoreSession.removeCertificatesByUsername(username);
            try {
                endEntityManagementSession.deleteUser(ADMIN, username);
            } catch (NoSuchEndEntityException e) {
            } // NOPMD
        }
    }

    /**
     * Tests RA enrollment using SLH-DSA-SHA2-128F algorithm and password authentication including testing wrong password and using password when certificate is required.
     */
    @Test
    public void testRASimpleenrollPasswordAuthUsingSlhDsa() throws Exception {
        final String pwd = genRandomPwd();
        final String username = "testRAPasswordAuthUsingSlhDsa" + genRandomUserName();
        try {
            EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            // Authentication using username
            config.setCert(estAlias, false);
            config.setUsername(estAlias, username);
            config.setPassword(estAlias, pwd);
            // Test case with invalid CA
            config.setDefaultCAID(estAlias, getTestCAId(TESTCA_NAME));
            globalConfigurationSession.saveConfiguration(ADMIN, config);

            //
            // 1. Make EST simpleenroll request, message is a simple PKCS#10 request, RFC7030 section 4.2.1
            //
            String requestDN = "CN=" + username + ",O=EJBCA,C=SE";
            PKCS10CertificationRequest p10 = generateCertReq(requestDN, null, null, null, null, slhdsa, "SLH-DSA-SHA2-128F");
            byte[] reqmsg = Base64.encode(p10.getEncoded());
            // Send request first without username, should give unauthorized
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 401,
                    "<html><head><title>Error</title></head><body>Invalid username or password</body></html>");
            // Send request without password, should give unauthorized
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 401,
                    "<html><head><title>Error</title></head><body>Invalid username or password</body></html>", username, null);
            // Send request with wrong password, should give unauthorized
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 401,
                    "<html><head><title>Error</title></head><body>Invalid username or password</body></html>", username, "foo123");
            // Send request with correct username and password, but alias requiring certificate, should give unauthorized
            config.setCert(estAlias, true);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 401,
                    "<html><head><title>Error</title></head><body>No client certificate supplied</body></html>", username, pwd);

            // Send request with correct username and password, but alias configured with an invalid CA, should not work
            config.setCert(estAlias, false);
            config.setDefaultCAID(estAlias, 123);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 400,
                    "<html><head><title>Error</title></head><body>The requested CA for EST alias 'EstRAModeBasicSystemTest' could not be found: 123</body></html>",
                    username, pwd);

            // Send request with correct username and password, should work
            config.setDefaultCAID(estAlias, getTestCAId(TESTCA_NAME));
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            byte[] resp = sendEstRequest(estAlias, "simpleenroll", reqmsg, 200, null, username, pwd);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertSimpleEnrollResponse(requestDN, resp, slhdsa, (X509Certificate) getTestCACert(TESTCA_NAME));

            final CAInfo serverCertCaInfo = CaTestUtils.getServerCertCaInfo(ADMIN);
            config.setDefaultCAID(estAlias, serverCertCaInfo.getCAId());
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // use simpleenroll to create a cert with same keypair from csr
            requestDN = "CN=" + username + "_second,O=EJBCA,C=SE";
            p10 = generateCertReq(requestDN, null, null, null, null, slhdsa, "SLH-DSA-SHA2-128F");
            reqmsg = Base64.encode(p10.getEncoded());

            resp = sendEstRequest(estAlias, "simpleenroll", reqmsg, 200, null, username, pwd);
            X509Certificate tlsReenrollCert = getCertFromResponse(resp);

            resp = sendEstRequest(estAlias, "serverkeygen", reqmsg, 200, null, username, pwd);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertKeyGenResponse(requestDN, resp, slhdsa);

            // subsequent key generation
            /* rest of the statement is not working as wildfly does not support SLH-DSA
            final KeyPair slhDsaNew = KeyTools.genKeys("SLH-DSA-44", AlgorithmConstants.KEYALGORITHM_SLH_DSA_SHA2_128F);
            final PKCS10CertificationRequest p10New = generateCertReq(requestDN, null, null, null, null, slhDsaNew, "SLH-DSA-SHA2-128F");
            final byte[] reqmsgNew = Base64.encode(p10New.getEncoded());
            X509Certificate oldCert = cert;

            setupClientKeyStore(serverCertCaInfo, slhDsa, tlsReenrollCert);
            resp = sendEstRequest(true, estAlias, "serverkeygen", reqmsgNew, 200, null, null, null);
            assertNotNull("There must be response data to simpleenroll request", resp);
            cert = getCertFromKeygenResponse(resp);
            assertEquals("serverkeygen response issuerDN must be our EST test CAs subjectDN", serverCertCaInfo.getSubjectDN(), CertTools.getIssuerDN(cert));
            try {
                cert.verify(serverCertCaInfo.getCertificateChain().get(0).getPublicKey());
            } catch (SignatureException e) {
                fail("serverkeygen response certifciate must verify with CA certificate");
            }
            assertEquals("serverkeygen response subjectDN must be our PKCS#10 request DN", requestDN, cert.getSubjectDN().toString());
            assertNotEquals("serverkeygen response public key must be the differant than the PKCS#10 request", Base64.toBase64String(slhDsaNew.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));
            assertNotEquals("serverkeygen response public key must be the differant than the old key", Base64.toBase64String(oldCert.getPublicKey().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));
            */

        } finally {
            // Remove the generated end entity and all the certificates
            internalCertStoreSession.removeCertificatesByUsername(username);
            try {
                endEntityManagementSession.deleteUser(ADMIN, username);
            } catch (NoSuchEndEntityException e) {
            } // NOPMD
        }
    }

    @Test
    public void testRASimpleenrollWithSans() throws Exception {
        final String pwd = genRandomPwd();
        final String username = "testRAPasswordAuthUsingSans" + genRandomUserName();
        try {
            final String requestDN = "CN=" + username;
            final X509Certificate testCaCert = (X509Certificate) getTestCACert(TESTCA_NAME);
            final PKCS10CertificationRequest p10 = generateCertReq(requestDN, null, null, null, getSanExtension(
                "dNSName=www.primekey.se,"
                + "ipAddress=127.0.0.1,"
                + "hardwareModuleName=1.2.3.4.99/serial1,"
                + "permanentIdentifier=ident1/1.2.3.4.99,"
                + "upn=abc123@abc,"
                + "guid=6d736775696431,"
                + "xmppAddr=xmppAddr1,"
                + "UNIFORMRESOURCEIDENTIFIER=www.keyfactor.com,"
                + "URI=uri.primekey.se,"
                + "REGISTEREDID=2.2.3.4.99,"
                + "rfc822Name=mail@primekey.se"), mldsa44, "ML-DSA-44");

            final byte[] reqmsg = Base64.encode(p10.getEncoded());

            final EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            config.setCert(estAlias, false);
            config.setUsername(estAlias, username);
            config.setPassword(estAlias, pwd);
            config.setEndEntityProfileID(estAlias, eepIdForSanTest);
            config.setCertProfileID(estAlias, cpId);
            config.setDefaultCAID(estAlias, getTestCAId(TESTCA_NAME));
            globalConfigurationSession.saveConfiguration(ADMIN, config);

            // Simple enroll the certificate. An end entity profile exception is thrown resulting in an not specific error message.
            byte[] response = sendEstRequest(estAlias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Exception encountered when performing EST operation 'simpleenroll' on alias 'EstRAModeBasicSystemTest'.</body></html>", username, pwd);

            final EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile(EEP_NAME_FOR_SAN_TEST);
            eep.addField(DnComponents.DNSNAME);
            eep.addField(DnComponents.IPADDRESS);
            eep.addField(DnComponents.HARDWAREMODULENAME);
            eep.addField(DnComponents.PERMANENTIDENTIFIER);
            eep.addField(DnComponents.UPN);
            eep.addField(DnComponents.GUID);
            eep.addField(DnComponents.XMPPADDR);
            eep.addField(DnComponents.UNIFORMRESOURCEID);
            eep.addField(DnComponents.UNIFORMRESOURCEID);
            eep.addField(DnComponents.REGISTEREDID);
            eep.addField(DnComponents.RFC822NAME);
            endEntityProfileSession.changeEndEntityProfile(ADMIN, EEP_NAME_FOR_SAN_TEST, eep);

            // Simple enroll the certificate including the 5 SANs.
            response = sendEstRequest(estAlias, "simpleenroll", reqmsg, 200, null, username, pwd);
            assertSimpleEnrollResponse(requestDN, response, mldsa44, testCaCert);
            X509Certificate cert = getCertFromResponse(response);
            assertSans(cert);

            // Allow extension override (not required, same result without).
            final CertificateProfile cp = certificateProfileSession.getCertificateProfile(cpId);
            cp.setAllowExtensionOverride(true);
            cp.setOverridableExtensionOIDs(Set.of("2.5.29.17"));
            certificateProfileSession.changeCertificateProfile(ADMIN, CP_NAME, cp);

            // Simple enroll the certificate including the 5 SANs.
            response = sendEstRequest(estAlias, "simpleenroll", reqmsg, 200, null, username, pwd);
            assertSimpleEnrollResponse(requestDN, response, mldsa44, testCaCert);
            cert = getCertFromResponse(response);
            assertSans(cert);
        } finally {
            // Remove the generated end entity and all the certificates
            internalCertStoreSession.removeCertificatesByUsername(username);
            try {
                endEntityManagementSession.deleteUser(ADMIN, username);
            } catch (NoSuchEndEntityException e) {
            } // NOPMD
        }
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    private final Extensions getSanExtension(final String subjectAltName) {
        final ExtensionsGenerator generator = new ExtensionsGenerator();
        final GeneralNames san = DnComponents.getGeneralNamesFromAltName(subjectAltName);
        try {
            generator.addExtension(Extension.subjectAlternativeName, false, san);
        } catch (IOException e) {
            log.error("Failed to add extensions: " + e.getMessage());
            log.error("debug", e);
        }
        return generator.generate();
    }

    private final void assertSimpleEnrollResponse(final String requestDn, final byte[] response, final KeyPair keyPair, final X509Certificate testcacert) throws Exception {
        assertNotNull("There must be response data to simpleenroll request", response);
        // final X509Certificate testcacert = (X509Certificate) getTestCACert(TESTCA_NAME);
        final X509Certificate cert = getCertFromResponse(response);

        assertEquals("simpleenroll response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(testcacert), CertTools.getIssuerDN(cert));
        try {
            cert.verify(testcacert.getPublicKey());
        } catch (SignatureException e) {
            fail("simpleenroll response certifciate must verify with CA certificate");
        }
        assertEquals("simpleenroll response subjectDN must be our PKCS#10 request DN", requestDn, cert.getSubjectDN().toString());
        assertEquals("simpleenroll response public key must be the same as the PKCS#10 request",
                Base64.toBase64String(keyPair.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));
    }

    private final void assertKeyGenResponse(final String requestDn, final byte[] response, final KeyPair keyPair) throws Exception {
        assertNotNull("There must be response data to serverkeygen request", response);
        final X509Certificate cert = getCertFromKeygenResponse(response);
        final CAInfo serverCertCaInfo = CaTestUtils.getServerCertCaInfo(ADMIN);

        // assertEquals("serverkeygen response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(testcacert), CertTools.getIssuerDN(cert));
        assertEquals("serverkeygen response issuerDN must be our EST test CAs subjectDN", serverCertCaInfo.getSubjectDN(), CertTools.getIssuerDN(cert));
        try {
            cert.verify(serverCertCaInfo.getCertificateChain().get(0).getPublicKey()); // testcacert.getPublicKey()
        } catch (SignatureException e) {
            fail("serverkeygen response certifciate must verify with CA certificate");
        }
        assertEquals("serverkeygen response subjectDN must be our PKCS#10 request DN", requestDn, cert.getSubjectDN().toString());
        assertNotEquals("serverkeygen response public key must be the differant than the PKCS#10 request",
                Base64.toBase64String(keyPair.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));
    }

    private final void assertSans(final X509Certificate certificate) {
        final String[] san = DnComponents.getSubjectAlternativeName(certificate).split(",");
        assertEquals("SAN DNS Name does not match.", "dNSName=www.primekey.se", san[0].trim());
        assertEquals("SAN IP address does not match.", "iPAddress=127.0.0.1", san[1].trim());
        assertEquals("SAN Hardware Module Name does not match.", "HARDWAREMODULENAME=1.2.3.4.99/serial1", san[2].trim());
        assertEquals("SAN Permanent Identifier does not match.", "PERMANENTIDENTIFIER=ident1/1.2.3.4.99", san[3].trim());
        assertEquals("SAN User Principal Name (MS UPN) does not match.", "UPN=abc123@abc", san[4].trim());
        assertEquals("SAN Globally Unique Identifier (MS GUID) does not match.", "guid=6d736775696431", san[5].trim());
        assertEquals("SAN XMPP Address does not match.", "XMPPADDR=xmppAddr1", san[6].trim());
        assertEquals("SAN uniform resource identifier does not match.", "UNIFORMRESOURCEIDENTIFIER=www.keyfactor.com", san[7].trim());
        assertEquals("SAN URI does not match.", "UNIFORMRESOURCEIDENTIFIER=uri.primekey.se", san[8].trim());
        assertEquals("SAN registered OID does not match.", "REGISTEREDID=2.2.3.4.99", san[9].trim());
        assertEquals("SAN RFC 822 Name does not match.", "rfc822name=mail@primekey.se", san[10].trim());
    }
}
