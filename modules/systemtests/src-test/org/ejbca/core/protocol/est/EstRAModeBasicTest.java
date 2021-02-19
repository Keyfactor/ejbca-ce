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
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.EstConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.ejbca.core.model.ra.UsernameGeneratorParams;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
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
    }

    @AfterClass
    public static void afterClass() {
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
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Tests getting CA certificates, when CA exists and when not. {@link EstAliasTest)} already tests cacerts for non existing aliases.
     */
    @Test
    public void testGetCACerts() throws Exception {
        log.trace(">testGetCACerts()");
        final String alias = "ESTRAGetCACertsTest";
        EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        try {
            config.addAlias(alias);
            config.setRAMode(alias, true); // RA mode
            // We don't need much in this alias to just get CA certificate
            config.setDefaultCAID(alias, getTestCAId(TESTCA_NAME));
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // Make EST cacerts request here
            byte[] resp = sendEstRequest(alias, "cacerts", null, 200); 
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.1.3
            assertNotNull("There must be response data to cacerts request", resp);
            final CMSSignedData msg = new CMSSignedData(Base64.decode(resp));
            final Store<X509CertificateHolder> certstore = msg.getCertificates();
            final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
            assertEquals("EST test CA has a single CA certificate", 1, certs.size());
            final X509Certificate testcacert = (X509Certificate)getTestCACert(TESTCA_NAME);
            assertEquals("cacerts response subjectDN must be our EST test CAs subjectDN", testcacert.getSubjectDN().getName(), certs.iterator().next().getSubject().toString());
        } finally {
            // Remove EST alias
            config.removeAlias(alias);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
        }        
        log.trace("<testGetCACerts()");
    }

    /**
     * Tests RA enrollment using password authentication including testing wrong password and using password when certificate is required.
     */
    @Test
    public void testRAPasswordAuth() throws Exception {
        log.trace(">testRAPasswordAuth()");
        final String alias = "ESTRARAPasswordAuth";
        final String pwd = genRandomPwd();
        final String username = "testRAPasswordAuth" + genRandomUserName();
        EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        try {
            config.addAlias(alias);
            config.setRAMode(alias, true); // RA mode
            config.setDefaultCAID(alias, getTestCAId(TESTCA_NAME));
            config.setEndEntityProfileID(alias, eepId);
            config.setCertProfileID(alias, cpId);
            // Generate password using the CN from the request subject DN as end entity username
            config.setRANameGenScheme(alias, UsernameGeneratorParams.DN);
            config.setRANameGenParams(alias, "CN");
            // Don't allow renewal with same user public key
            config.setKurAllowSameKey(alias, false); 
            // Authentication using username
            config.setCert(alias, false);
            config.setUsername(alias, username);
            config.setPassword(alias, pwd);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            
            //
            // 1. Make EST simpleenroll request, message is a simple PKCS#10 request, RFC7030 section 4.2.1
            //
            final String requestDN = "CN=" + username + ",O=EJBCA,C=SE";
            PKCS10CertificationRequest p10 = generateCertReq(requestDN, null, null, ec256);
            byte[] reqmsg = Base64.encode(p10.getEncoded());
            // Send request first without username, should give unauthorized
            sendEstRequest(alias, "simpleenroll", reqmsg, 401); 
            // Send request without password, should give unauthorized
            sendEstRequest(alias, "simpleenroll", reqmsg, 401, username, null); 
            // Send request with wrong password, should give unauthorized
            sendEstRequest(alias, "simpleenroll", reqmsg, 401, username, "foo123"); 
            // Send request with correct username and password, but alias requiring certificate, shoudl give unauthorized
            config.setCert(alias, true);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            sendEstRequest(alias, "simpleenroll", reqmsg, 401, username, pwd); 
            // Send request with correct username and password, should work
            config.setCert(alias, false);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            byte[] resp = sendEstRequest(alias, "simpleenroll", reqmsg, 200, username, pwd); 
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            final CMSSignedData respmsg = new CMSSignedData(Base64.decode(resp));
            final Store<X509CertificateHolder> certstore = respmsg.getCertificates();
            final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
            assertEquals("EST simpleenroll shoud return a single certificate", 1, certs.size());
            final X509Certificate testcacert = (X509Certificate)getTestCACert(TESTCA_NAME);
            final X509CertificateHolder certHolder = certs.iterator().next();
            final X509Certificate cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
            assertEquals("simpleenroll response issuerDN must be our EST test CAs subjectDN", testcacert.getSubjectDN().getName(), cert.getIssuerDN().toString());
            try {
                cert.verify(testcacert.getPublicKey());
            } catch (SignatureException e) {
                fail("simpleenroll response certifciate must verify with CA certificate");                
            }
            assertEquals("simpleenroll response subjectDN must be our PKCS#10 request DN", requestDN, cert.getSubjectDN().toString());
            assertEquals("simpleenroll response public key must be the same as the PKCS#10 request", Base64.toBase64String(ec256.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));
            
            //
            // 2. Make EST simplereenroll request, message is a simple PKCS#10 request, RFC7030 section 4.2.2
            //
            // No client certificate should give unauthorized, regardless if we have username/pwd or not
            sendEstRequest(alias, "simplereenroll", reqmsg, 401, username, pwd); 
            sendEstRequest(alias, "simplereenroll", reqmsg, 401, null, null); 
            // TODO: add with actual client cert authentication, needs to use Management CA...

        } finally {
            // Remove EST alias
            config.removeAlias(alias);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // Remove the generated end entity and all the certificates
            internalCertStoreSession.removeCertificatesByUsername(username);
            endEntityManagementSession.deleteUser(ADMIN, username);
        }        
        log.trace("<testRAPasswordAuth()");
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

}
