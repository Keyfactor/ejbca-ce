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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.apache.log4j.Logger;
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
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.EstConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.ra.UsernameGeneratorParams;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.string.StringConfigurationCache;

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
public class EstRAModeBasicTest extends EstTestCase {

    private static final Logger log = Logger.getLogger(EstRAModeBasicTest.class);

    private static final String TESTCA_NAME = EstRAModeBasicTest.class.getSimpleName();
    private static boolean isESTEnabled = false; // if EST was enabled or not before running test 
    
    private static final GlobalConfigurationSession globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static KeyPair ec256;
    private static String estAlias = "EstRAModeBasicTest";
    
    @BeforeClass
    public static void beforeClass() throws CADoesntExistsException, CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, AuthorizationDeniedException, InvalidAlgorithmParameterException {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        CryptoProviderTools.installBCProvider();
        createTestCA(TESTCA_NAME); // Create test CA
        
        // Enable EST. EstAliasTest tests responses when disabled so here we only want to test enabled functionality
        AvailableProtocolsConfiguration protConf = ((AvailableProtocolsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID));
        isESTEnabled = protConf.getProtocolStatus("EST");
        if (!isESTEnabled) {
            // Enable if not enabled
            protConf.setProtocolStatus("EST", true);
            globalConfigurationSession.saveConfiguration(ADMIN, protConf);
        }
        ec256 = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
        
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
        config.setRANameGenScheme(estAlias, UsernameGeneratorParams.DN);
        config.setRANameGenParams(estAlias, "CN");
        // Don't allow renewal with same user public key
        config.setKurAllowSameKey(estAlias, false); 
        config.setServerKeyGenerationEnabled(estAlias, true); 
        globalConfigurationSession.saveConfiguration(ADMIN, config);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        // Remove EST alias
        final EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        config.removeAlias(estAlias);
        globalConfigurationSession.saveConfiguration(ADMIN, config);
    }

    /**
     * Tests getting CA certificates, when CA exists and when not. {@link EstAliasTest)} already tests cacerts for non existing aliases.
     */
    @Test
    public void testGetCACerts() throws Exception {
        log.trace(">testGetCACerts()");
        try {
            // Make EST cacerts request here
            byte[] resp = sendEstRequest(estAlias, "cacerts", null, 200, null); 
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.1.3
            assertNotNull("There must be response data to cacerts request", resp);
            final CMSSignedData msg = new CMSSignedData(Base64.decode(resp));
            final Store<X509CertificateHolder> certstore = msg.getCertificates();
            final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
            assertEquals("EST test CA has a single CA certificate", 1, certs.size());
            final X509Certificate testcacert = (X509Certificate)getTestCACert(TESTCA_NAME);
            assertEquals("cacerts response subjectDN must be our EST test CAs subjectDN", testcacert.getSubjectDN().getName(), certs.iterator().next().getSubject().toString());
        } finally {
        }        
        log.trace("<testGetCACerts()");
    }

    /**
     * Tests RA enrollment using password authentication including testing wrong password and using password when certificate is required.
     */
    @Test
    public void testRASimpleenrollPasswordAuth() throws Exception {
        log.trace(">testRASimpleenrollPasswordAuth()");
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
            PKCS10CertificationRequest p10 = generateCertReq(requestDN, null, null, null, null, ec256);
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
            sendEstRequest(estAlias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>The requested CA for EST alias 'EstRAModeBasicTest' could not be found: 123</body></html>", username, pwd); 

            // Send request with correct username and password, should work
            config.setDefaultCAID(estAlias, getTestCAId(TESTCA_NAME));
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            byte[] resp = sendEstRequest(estAlias, "simpleenroll", reqmsg, 200, null, username, pwd); 
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            final X509Certificate testcacert = (X509Certificate)getTestCACert(TESTCA_NAME);
            X509Certificate cert = getCertFromResponse(resp);
            assertEquals("simpleenroll response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(testcacert), CertTools.getIssuerDN(cert));
            try {
                cert.verify(testcacert.getPublicKey());
            } catch (SignatureException e) {
                fail("simpleenroll response certifciate must verify with CA certificate");                
            }
            assertEquals("simpleenroll response subjectDN must be our PKCS#10 request DN", requestDN, cert.getSubjectDN().toString());
            assertEquals("simpleenroll response public key must be the same as the PKCS#10 request", Base64.toBase64String(ec256.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));   
            
            final CAInfo serverCertCaInfo = CaTestUtils.getServerCertCaInfo(ADMIN);
            config.setDefaultCAID(estAlias, serverCertCaInfo.getCAId()); 
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // use simpleenroll to create a cert with same keypair from csr
            requestDN = "CN=" + username + "_second,O=EJBCA,C=SE";
            p10 = generateCertReq(requestDN, null, null, null, null, ec256);
            reqmsg = Base64.encode(p10.getEncoded());
            
            resp = sendEstRequest(estAlias, "simpleenroll", reqmsg, 200, null, username, pwd); 
            X509Certificate tlsReenrollCert = getCertFromResponse(resp);
            
            resp = sendEstRequest(estAlias, "serverkeygen", reqmsg, 200, null, username, pwd); 
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            cert = getCertFromKeygenResponse(resp);
            assertEquals("serverkeygen response issuerDN must be our EST test CAs subjectDN", serverCertCaInfo.getSubjectDN(), CertTools.getIssuerDN(cert));
            try {
                cert.verify(serverCertCaInfo.getCertificateChain().get(0).getPublicKey());
            } catch (SignatureException e) {
                fail("serverkeygen response certifciate must verify with CA certificate");                
            }
            assertEquals("serverkeygen response subjectDN must be our PKCS#10 request DN", requestDN, cert.getSubjectDN().toString());
            assertNotEquals("serverkeygen response public key must be the differant than the PKCS#10 request", Base64.toBase64String(ec256.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));            
            
            // subsequent key generation
            final KeyPair ec256New = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
            final PKCS10CertificationRequest p10New = generateCertReq(requestDN, null, null, null, null, ec256New);
            final byte[] reqmsgNew = Base64.encode(p10New.getEncoded());
            X509Certificate oldCert = cert;
            
            setupClientKeyStore(serverCertCaInfo, ec256, tlsReenrollCert);
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
            assertNotEquals("serverkeygen response public key must be the differant than the PKCS#10 request", Base64.toBase64String(ec256New.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));            
            assertNotEquals("serverkeygen response public key must be the differant than the old key", Base64.toBase64String(oldCert.getPublicKey().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));            

        } finally {
            // Remove the generated end entity and all the certificates
            internalCertStoreSession.removeCertificatesByUsername(username);
            try {
                endEntityManagementSession.deleteUser(ADMIN, username);
            } catch (NoSuchEndEntityException e) {} // NOPMD
        }        
        log.trace("<testRASimpleenrollPasswordAuth()");
    }
    
    /**
     * Tests RA enrollment using certificate authentication including testing wrong password and using password when certificate is required.
     */
    @Test
    public void testRASimpleenrollCertAuth() throws Exception {
        log.trace(">testRASimpleenrollCertAuth()");
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
            final PKCS10CertificationRequest p10Admin = generateCertReq(adminRequestDN, null, null, null, null, ec256Admin);
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
            PKCS10CertificationRequest p10 = generateCertReq(requestDN, null, null, null, null, ec256);
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
            final X509Certificate testcacert = (X509Certificate)serverCertCaInfo.getCertificateChain().get(0);
            cert = CertTools.getCertfromByteArray(certs.iterator().next().getEncoded(), X509Certificate.class);
            assertEquals("simpleenroll response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(testcacert), CertTools.getIssuerDN(cert));
            try {
                cert.verify(testcacert.getPublicKey());
            } catch (SignatureException e) {
                fail("simpleenroll response certifciate must verify with CA certificate");                
            }
            assertEquals("simpleenroll response subjectDN must be our PKCS#10 request DN", requestDN, cert.getSubjectDN().toString());
            assertEquals("simpleenroll response public key must be the same as the PKCS#10 request", Base64.toBase64String(ec256.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));   
            
            resp = sendEstRequest(true, estAlias, "serverkeygen", reqmsg, 200, null, null, null); 
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to serverkeygen request", resp);
            cert = getCertFromKeygenResponse(resp);
            assertEquals("serverkeygen response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(testcacert), CertTools.getIssuerDN(cert));
            try {
                cert.verify(testcacert.getPublicKey());
            } catch (SignatureException e) {
                fail("serverkeygen response certifciate must verify with CA certificate");                
            }
            assertEquals("serverkeygen response subjectDN must be our PKCS#10 request DN", requestDN, cert.getSubjectDN().toString());
            assertNotEquals("serverkeygen response public key must be the same as the PKCS#10 request", Base64.toBase64String(ec256.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));            
                    
        } finally {
            // Remove from super admin role
            if (member != null) {
                removeFromSuperAdminRole(member.getId());
            }
            // Remove the generated end entity and all the certificates
            internalCertStoreSession.removeCertificatesByUsername(clientUsername);
            try {
                endEntityManagementSession.deleteUser(ADMIN, clientUsername);
            } catch (NoSuchEndEntityException e) {} // NOPMD
            internalCertStoreSession.removeCertificatesByUsername(adminUsername);
            try {
                endEntityManagementSession.deleteUser(ADMIN, adminUsername);
            } catch (NoSuchEndEntityException e) {} // NOPMD
        }        
        log.trace("<testRASimpleenrollCertAuth()");
    }

    /**
     * Tests re-enrollment with EST alias in RA mode including wrong enrolment with missmatch between TLS cert and CSR as well as revoked TLS cert.
     */
    @Test
    public void testRASimpleReenroll() throws Exception {
        log.trace(">testRASimpleReenroll()");
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
            final PKCS10CertificationRequest p10 = generateCertReq(requestDN, null, null, null, null, ec256);
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
            sendEstRequest(true, estAlias, "simplereenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Exception encountered when performing EST operation 'simplereenroll' on alias 'EstRAModeBasicTest'.</body></html>", 
                    null, null);
            // A new request with new keys, but with the same subject DN should succeed
            final KeyPair ec256New = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
            final PKCS10CertificationRequest p10New = generateCertReq(requestDN, null, null, null, null, ec256New);
            final byte[] reqmsgNew = Base64.encode(p10New.getEncoded());
            resp = sendEstRequest(true, estAlias, "simplereenroll", reqmsgNew, 200, null, null, null);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            respmsg = new CMSSignedData(Base64.decode(resp));
            certs = respmsg.getCertificates().getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, certs.size());
            final X509Certificate testcacert = (X509Certificate)serverCertCaInfo.getCertificateChain().get(0);
            cert = CertTools.getCertfromByteArray(certs.iterator().next().getEncoded(), X509Certificate.class);
            assertEquals("simpleenroll response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(testcacert), CertTools.getIssuerDN(cert));
            try {
                cert.verify(testcacert.getPublicKey());
            } catch (SignatureException e) {
                fail("simpleenroll response certifciate must verify with CA certificate");                
            }
            assertEquals("simpleenroll response subjectDN must be our PKCS#10 request DN", requestDN, cert.getSubjectDN().toString());
            assertEquals("simpleenroll response public key must be the same as the PKCS#10 request", Base64.toBase64String(ec256New.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));
            // Checking for enrollment with the same public key only compares the TLS cert (reenroll authentication) with the CSR, it does not loop through all existing client certificates
            // so a failed reenroll can be retried with the same CSR, therefore it should work to reenroll with the same (new) CSR as long as we use the old key for TLS authentication
            resp = sendEstRequest(true, estAlias, "simplereenroll", reqmsgNew, 200, null, null, null);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            
            // Try again, but now using the new key for TLS authentication as well, not allowing same keys should give an error as above with the new request as well
            setupClientKeyStore(serverCertCaInfo, ec256New, cert);
            sendEstRequest(true, estAlias, "simplereenroll", reqmsgNew, 400, "<html><head><title>Error</title></head><body>Exception encountered when performing EST operation 'simplereenroll' on alias 'EstRAModeBasicTest'.</body></html>", 
                    null, null);
            // Modify alias to allow same keys
            config.setKurAllowSameKey(estAlias, true);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            resp =  sendEstRequest(true, estAlias, "simplereenroll", reqmsgNew, 200, null, null, null);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            respmsg = new CMSSignedData(Base64.decode(resp));
            certs = respmsg.getCertificates().getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, certs.size());

            // Change the subject DN in the CSR, should not be allowed to reenroll now
            // Log will show: 11:11:45,539 INFO  [org.ejbca.core.protocol.est.EstOperationsSessionBean] (default task-4) Can't reenroll using different subject than requesting certificate. Request DN='CN=ESTRARAReenroll204554,OU=Test,O=EJBCA,C=SE'
            final PKCS10CertificationRequest p10NewDN = generateCertReq(requestDN + ",OU=Test", null, null, null, null, ec256New);
            final byte[] reqmsgNewDN = Base64.encode(p10NewDN.getEncoded());
            sendEstRequest(true, estAlias, "simplereenroll", reqmsgNewDN, 400, "<html><head><title>Error</title></head><body>Exception encountered when performing EST operation 'simplereenroll' on alias 'EstRAModeBasicTest'.</body></html>", 
                    null, null);
        } finally {
            // Remove the generated end entity and all the certificates
            internalCertStoreSession.removeCertificatesByUsername(username);
            try {
                endEntityManagementSession.deleteUser(ADMIN, username);
            } catch (NoSuchEndEntityException e) {} // NOPMD
        }        
        log.trace("<testRASimpleReenroll()");
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

}
