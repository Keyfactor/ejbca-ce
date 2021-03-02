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
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
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
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
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
 * Tests basic EST client mode. Initial enrollment and re-enrollment to pre-registered end entity using the end entity password for initial authorization.
 * Including basic error cases: malicious request (too large), invalid CSR encoding, no end entity found for initial enrollment or re-enrollment
 */
public class EstClientModeBasicTest extends EstTestCase {

    private static final Logger log = Logger.getLogger(EstClientModeBasicTest.class);

    private static final String TESTCA_NAME = EstClientModeBasicTest.class.getSimpleName();
    private static final String CN = "EstTestUser";
    private static KeyPair ec256;
    private static boolean isESTEnabled = false; // if EST was enabled or not before running test 
    
    private static final GlobalConfigurationSession globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    
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
        final String alias = "ESTGetCACertsTest";
        EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        try {
            config.addAlias(alias);
            config.setRAMode(alias, false); // client mode
            // We don't need much in this alias to just get CA certificate
            config.setDefaultCAID(alias, getTestCAId(TESTCA_NAME));
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // Make EST cacerts request here
            byte[] resp = sendEstRequest(alias, "cacerts", null, 200, null);
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

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
    
    @Test
    public void testSimpleEnrollWithChallengePwd() throws Exception {
        log.trace(">testSimpleEnrollWithChallengePwd()");
        final String alias = "ESTSimpleEnrollChallengePwd";
        
        EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        try {
            // Create alias
            config.addAlias(alias);
            config.setRAMode(alias, false); 
            config.setAuthenticationModule(alias, EstConfiguration.CONFIG_AUTHMODULE_CHALLENGE_PWD);
            config.setExtractUsernameComponent(alias, "CN");
            config.setDefaultCAID(alias, getTestCAId(TESTCA_NAME));
            config.setChangeSubjectName(alias, true);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // Create EE
            EndEntityInformation endEntityInfo = new EndEntityInformation();
            endEntityInfo.setUsername(CN);
            endEntityInfo.setPassword("foo123");
            endEntityInfo.setEndEntityProfileId(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            endEntityInfo.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            endEntityInfo.setCAId(getTestCAId(TESTCA_NAME));
            endEntityInfo.setDN("CN=OP,O=EJBCA,C=SE");
            endEntityInfo.setTokenType(EndEntityConstants.TOKEN_USERGEN);
            endEntityInfo.setType(EndEntityTypes.ENDUSER.toEndEntityType());
            endEntityInfo.setStatus(EndEntityConstants.STATUS_NEW);
            endEntityManagementSession.addUser(ADMIN, endEntityInfo, false);
            // Make EST simpleenroll request
            final String requestDN = "CN=" + CN + ",O=EJBCA,C=SE";
            final String pwd = "foo123";
            PKCS10CertificationRequest p10 = generateCertReq(requestDN, pwd, null, ec256);
            byte[] reqmsg = Base64.encode(p10.getEncoded());
            byte[] resp = sendEstRequest(alias, "simpleenroll", reqmsg, 200, null); 
            assertNotNull("There must be response data to simpleenroll request", resp);
            final CMSSignedData respmsg = new CMSSignedData(Base64.decode(resp));
            final Store<X509CertificateHolder> certstore = respmsg.getCertificates();
            final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
            assertEquals("EST simpleenroll shoud return a single certificate", 1, certs.size());
            final X509Certificate testcacert = (X509Certificate)getTestCACert(TESTCA_NAME);
            final X509CertificateHolder certHolder = certs.iterator().next();
            final X509Certificate cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
            assertEquals("simpleenroll response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(testcacert), CertTools.getIssuerDN(cert));
            try {
                cert.verify(testcacert.getPublicKey());
            } catch (SignatureException e) {
                fail("simpleenroll response certifciate must verify with CA certificate");                
            }
            assertEquals("simpleenroll response subjectDN must be DN from the pre-registered user, not the PKCS#10 DN", "CN=OP,O=EJBCA,C=SE", CertTools.getSubjectDN(cert));
            assertEquals("simpleenroll response public key must be the same as the PKCS#10 request", Base64.toBase64String(ec256.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));            
        } finally {
            // Remove the certificates
            internalCertStoreSession.removeCertificatesByUsername(CN);
            // Remove EST alias
            config.removeAlias(alias);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // Remove end entity
            endEntityManagementSession.deleteUser(ADMIN, CN);
        }        
        log.trace("<testSimpleEnrollWithChallengePwd()");
    }

}
