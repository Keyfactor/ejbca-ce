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
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
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
    private static final String CN = "EstClientModeTestUser";
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
            config.setOperationMode(alias, EstConfiguration.OPERATION_MODE_CLIENT); // client mode
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
    
    /**
     * Tests Client mode enrollment using password authentication, using ChallengePwd from the CSR, including testing wrong password.
     */
    @Test
    public void testSimpleEnrollWithChallengePwd() throws Exception {
        log.trace(">testSimpleEnrollWithChallengePwd()");
        final String alias = "ESTSimpleEnrollChallengePwd";
        
        EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        try {
            // Create alias
            config.addAlias(alias);
            config.setOperationMode(alias, EstConfiguration.OPERATION_MODE_CLIENT); // client mode
            config.setAuthenticationModule(alias, EstConfiguration.CONFIG_AUTHMODULE_CHALLENGE_PWD);
            config.setExtractUsernameComponent(alias, "CN");
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            
            // First make request without any EE created
            // Make EST simpleenroll request
            final String requestDN = "CN=" + CN + ",O=EJBCA,C=SE";
            PKCS10CertificationRequest p10 = generateCertReq(requestDN, "foo123", null, null, null, ec256);
            byte[] reqmsg = Base64.encode(p10.getEncoded());
            sendEstRequest(alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Invalid username, enrollment code, or end entity status</body></html>", null, null); 

            // Create EE
            EndEntityInformation endEntityInfo = new EndEntityInformation();
            endEntityInfo.setUsername(CN);
            endEntityInfo.setPassword("bar123");
            endEntityInfo.setEndEntityProfileId(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            endEntityInfo.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            endEntityInfo.setCAId(getTestCAId(TESTCA_NAME));
            endEntityInfo.setDN("CN=" + CN + ",O=EJBCA,C=SE");
            endEntityInfo.setTokenType(EndEntityConstants.TOKEN_USERGEN);
            endEntityInfo.setType(EndEntityTypes.ENDUSER.toEndEntityType());
            endEntityInfo.setStatus(EndEntityConstants.STATUS_NEW);
            endEntityManagementSession.addUser(ADMIN, endEntityInfo, false);
            
            // Make EST simpleenroll request again with a EE created, but wrong enrollment code
            reqmsg = Base64.encode(p10.getEncoded());
            sendEstRequest(alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Invalid username, enrollment code, or end entity status</body></html>", null, null); 

            // Make request with correct enrollment code
            p10 = generateCertReq(requestDN, "bar123", null, null, null, ec256);
            reqmsg = Base64.encode(p10.getEncoded());
            byte[] resp = sendEstRequest(alias, "simpleenroll", reqmsg, 200, null); 
            assertNotNull("There must be response data to simpleenroll request", resp);
            final CMSSignedData respmsg = new CMSSignedData(Base64.decode(resp));
            final Store<X509CertificateHolder> certstore = respmsg.getCertificates();
            final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, certs.size());
            final X509Certificate testcacert = (X509Certificate)getTestCACert(TESTCA_NAME);
            final X509CertificateHolder certHolder = certs.iterator().next();
            X509Certificate cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
            assertEquals("simpleenroll response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(testcacert), CertTools.getIssuerDN(cert));
            try {
                cert.verify(testcacert.getPublicKey());
            } catch (SignatureException e) {
                fail("simpleenroll response certifciate must verify with CA certificate");                
            }
            assertEquals("simpleenroll response subjectDN must be the same DN as the PKCS#10 request DN",requestDN, CertTools.getSubjectDN(cert));
            assertEquals("simpleenroll response public key must be the same as the PKCS#10 request", Base64.toBase64String(ec256.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));  
            
            testServerKeyGen(alias, reqmsg, testcacert, endEntityInfo);
        } finally {
            // Remove the certificates
            internalCertStoreSession.removeCertificatesByUsername(CN);
            // Remove EST alias
            config.removeAlias(alias);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // Remove end entity
            try {
                endEntityManagementSession.deleteUser(ADMIN, CN);
            } catch (NoSuchEndEntityException e) {} // NOPMD
        }        
        log.trace("<testSimpleEnrollWithChallengePwd()");
    }

    /**
     * Tests Client mode enrollment using password authentication, using DnPwd from the CSR request DN, including testing wrong password.
     */
    @Test
    public void testSimpleEnrollWithDnPwd() throws Exception {
        log.trace(">testSimpleEnrollWithDnPwd()");
        final String alias = "ESTSimpleEnrollDnPwd";
        
        EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        try {
            // Create alias
            config.addAlias(alias);
            config.setOperationMode(alias, EstConfiguration.OPERATION_MODE_CLIENT); // client mode
            config.setAuthenticationModule(alias, EstConfiguration.CONFIG_AUTHMODULE_DN_PART_PWD);
            config.setExtractDnPwdComponent(alias, "SN"); // SN == SERIALNUMBER 
            config.setExtractUsernameComponent(alias, "CN");
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            
            // First make request without any EE created
            // Make EST simpleenroll request
            String requestDN = "CN=" + CN + ",O=EJBCA,C=SE";
            PKCS10CertificationRequest p10 = generateCertReq(requestDN, null, null, null, null, ec256); // no challenge password
            byte[] reqmsg = Base64.encode(p10.getEncoded());
            sendEstRequest(alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Invalid username, enrollment code, or end entity status</body></html>", null, null); 

            // Create EE
            EndEntityInformation endEntityInfo = new EndEntityInformation();
            endEntityInfo.setUsername(CN);
            endEntityInfo.setPassword("bar123");
            endEntityInfo.setEndEntityProfileId(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            endEntityInfo.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            endEntityInfo.setCAId(getTestCAId(TESTCA_NAME));
            endEntityInfo.setDN("CN=" + CN + ",O=EJBCA,C=SE");
            endEntityInfo.setTokenType(EndEntityConstants.TOKEN_USERGEN);
            endEntityInfo.setType(EndEntityTypes.ENDUSER.toEndEntityType());
            endEntityInfo.setStatus(EndEntityConstants.STATUS_NEW);
            endEntityManagementSession.addUser(ADMIN, endEntityInfo, false);
            
            // Make EST simpleenroll request again with a EE created, but no extractable enrollment code
            reqmsg = Base64.encode(p10.getEncoded());
            sendEstRequest(alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Could not extract password from CSR request using the DnPartPwd authentication module</body></html>", null, null); 

            // Make EST simpleenroll request again with a EE created, but wrong enrollment code
            requestDN = "CN=" + CN + ",SERIALNUMBER=foo123,O=EJBCA,C=SE";
            p10 = generateCertReq(requestDN, null, null, null, null, ec256); // no challenge password
            reqmsg = Base64.encode(p10.getEncoded());
            sendEstRequest(alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Invalid username, enrollment code, or end entity status</body></html>", null, null); 

            // with challenge password that is the correct enrollment code, should not be used
            p10 = generateCertReq(requestDN, "bar123", null, null, null, ec256); 
            reqmsg = Base64.encode(p10.getEncoded());
            sendEstRequest(alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Invalid username, enrollment code, or end entity status</body></html>", null, null); 

            // Set the correct pwd, matching the SERIALNUMBER in request DN 
            requestDN = "CN=" + CN + ",SERIALNUMBER=bar123,O=EJBCA,C=SE";
            p10 = generateCertReq(requestDN, null, null, null, null, ec256); // no challenge password
            reqmsg = Base64.encode(p10.getEncoded());
            byte[] resp = sendEstRequest(alias, "simpleenroll", reqmsg, 200, null); 
            assertNotNull("There must be response data to simpleenroll request", resp);
            final CMSSignedData respmsg = new CMSSignedData(Base64.decode(resp));
            final Store<X509CertificateHolder> certstore = respmsg.getCertificates();
            final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, certs.size());
            final X509Certificate testcacert = (X509Certificate)getTestCACert(TESTCA_NAME);
            final X509CertificateHolder certHolder = certs.iterator().next();
            X509Certificate cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
            assertEquals("simpleenroll response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(testcacert), CertTools.getIssuerDN(cert));
            try {
                cert.verify(testcacert.getPublicKey());
            } catch (SignatureException e) {
                fail("simpleenroll response certifciate must verify with CA certificate");                
            }
            assertEquals("simpleenroll response subjectDN must be the same DN as the PKCS#10 request DN",endEntityInfo.getDN(), CertTools.getSubjectDN(cert));
            assertEquals("simpleenroll response public key must be the same as the PKCS#10 request", Base64.toBase64String(ec256.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));   
            
            testServerKeyGen(alias, reqmsg, testcacert, endEntityInfo);
        } finally {
            // Remove the certificates
            internalCertStoreSession.removeCertificatesByUsername(CN);
            // Remove EST alias
            config.removeAlias(alias);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // Remove end entity
            try {
                endEntityManagementSession.deleteUser(ADMIN, CN);
            } catch (NoSuchEndEntityException e) {} // NOPMD
        }        
        log.trace("<testSimpleEnrollWithDnPwd()");
    }


    /**
     * Tests Client mode enrollment using password authentication, using ChallengePwd from the CSR, including testing wrong password.
     */
    @Test
    public void testSimpleEnrollWithChallengePwdAndUsernameInDn() throws Exception {
        log.trace(">testSimpleEnrollWithChallengePwdAndUsernameInDn()");
        final String alias = "testEnrollWithdUsernameInDn";
        final String username = "EstClientTestUsername";


        EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        try {
            // Create alias
            config.addAlias(alias);
            config.setOperationMode(alias, EstConfiguration.OPERATION_MODE_CLIENT); // client mode
            config.setAuthenticationModule(alias, EstConfiguration.CONFIG_AUTHMODULE_CHALLENGE_PWD);
            config.setExtractUsernameComponent(alias, "UID");
            globalConfigurationSession.saveConfiguration(ADMIN, config);

            // Create EE
            EndEntityInformation endEntityInfo = new EndEntityInformation();
            endEntityInfo.setUsername(username);
            endEntityInfo.setPassword("bar123");
            endEntityInfo.setEndEntityProfileId(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            endEntityInfo.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            endEntityInfo.setCAId(getTestCAId(TESTCA_NAME));
            endEntityInfo.setDN("CN=" + CN + ",O=EJBCA,C=SE");
            endEntityInfo.setTokenType(EndEntityConstants.TOKEN_USERGEN);
            endEntityInfo.setType(EndEntityTypes.ENDUSER.toEndEntityType());
            endEntityInfo.setStatus(EndEntityConstants.STATUS_NEW);
            endEntityManagementSession.addUser(ADMIN, endEntityInfo, false);


            // Make request with username in DN
            final String dn = "CN=" + CN + ",O=EJBCA,C=SE";
            final String requestDN = "UID=" + username + "," + dn;
            PKCS10CertificationRequest p10 = generateCertReq(requestDN, "bar123", null, null, null, ec256);
            byte[] reqmsg = Base64.encode(p10.getEncoded());
            byte[] resp = sendEstRequest(alias, "simpleenroll", reqmsg, 200, null);
            assertNotNull("There must be response data to simpleenroll request", resp);
            final CMSSignedData respmsg = new CMSSignedData(Base64.decode(resp));
            final Store<X509CertificateHolder> certstore = respmsg.getCertificates();
            final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, certs.size());
            final X509Certificate testcacert = (X509Certificate)getTestCACert(TESTCA_NAME);
            final X509CertificateHolder certHolder = certs.iterator().next();
            final X509Certificate cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
            assertEquals("simpleenroll response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(testcacert), CertTools.getIssuerDN(cert));
            try {
                cert.verify(testcacert.getPublicKey());
            } catch (SignatureException e) {
                fail("simpleenroll response certifciate must verify with CA certificate");
            }
            assertEquals("simpleenroll response subjectDN must be the same DN as the PKCS#10 request DN",dn, CertTools.getSubjectDN(cert));
            assertEquals("simpleenroll response public key must be the same as the PKCS#10 request", Base64.toBase64String(ec256.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));
            
            testServerKeyGen(alias, reqmsg, testcacert, endEntityInfo);
        } finally {
            // Remove the certificates
            internalCertStoreSession.removeCertificatesByUsername(username);
            // Remove EST alias
            config.removeAlias(alias);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // Remove end entity
            try {
                endEntityManagementSession.deleteUser(ADMIN, username);
            } catch (NoSuchEndEntityException e) {} // NOPMD
        }
        log.trace("<testSimpleEnrollWithChallengePwdAndUsernameInDn()");
    }
    
    private void testServerKeyGen(String alias, byte[] reqmsg,  X509Certificate testcacert, EndEntityInformation endEntityInfo) throws Exception {
        endEntityInfo.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityManagementSession.changeUser(ADMIN, endEntityInfo, false);
        
        byte[] resp = sendEstRequest(alias, "serverkeygen", reqmsg, 200, null); 
        // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
        assertNotNull("There must be response data to serverkeygen request", resp);
        X509Certificate cert = getCertFromKeygenResponse(resp);
        assertEquals("serverkeygen response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(testcacert), CertTools.getIssuerDN(cert));
        try {
            cert.verify(testcacert.getPublicKey());
        } catch (SignatureException e) {
            fail("serverkeygen response certifciate must verify with CA certificate");                
        }
        assertEquals("serverkeygen response subjectDN must be our PKCS#10 request DN", endEntityInfo.getDN(), CertTools.getSubjectDN(cert));
        assertNotEquals("serverkeygen response public key must be the same as the PKCS#10 request", Base64.toBase64String(ec256.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));            
        
    }

    /**
     * Tests re-enrollment with EST alias in Client mode including wrong enrolment with missmatch between TLS cert and CSR as well as revoked TLS cert.
     */
    @Test
    public void testSimpleReenroll() throws Exception {
        log.trace(">testSimpleReenroll()");
        final String alias = "ESTClientSimpleReEnroll";

        final EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        try {
            // Create EST Alias
            config.addAlias(alias);
            config.setOperationMode(alias, EstConfiguration.OPERATION_MODE_CLIENT); // client mode
            config.setAuthenticationModule(alias, EstConfiguration.CONFIG_AUTHMODULE_CHALLENGE_PWD);
            config.setExtractUsernameComponent(alias, "CN");
            config.setKurAllowSameKey(alias, false);
            // In order to re-enroll we need to be able to establish a TLS connection with client authentication, which means
            // that we need a client certificate issued from ManagementCA, which is an accepted CA for TLS client certs
            // We also need to enroll against port 8443
            // Apart from that we use the same EST alias as for enrollment test
            // Trusted CA setup: import CA that issued server certificate into trustedKeyStore (configurable with target.servercert.ca)
            final CAInfo serverCertCaInfo = CaTestUtils.getServerCertCaInfo(ADMIN);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            
            //
            // 1. Issue a first certificate with a EST simpleenroll request, message is a simple PKCS#10 request, RFC7030 section 4.2.1
            //
            // Create EE
            EndEntityInformation endEntityInfo = new EndEntityInformation();
            endEntityInfo.setUsername(CN);
            endEntityInfo.setPassword("foo123");
            endEntityInfo.setEndEntityProfileId(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            endEntityInfo.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            endEntityInfo.setCAId(serverCertCaInfo.getCAId());
            endEntityInfo.setDN("CN=" + CN + ",O=EJBCA,C=SE");
            endEntityInfo.setTokenType(EndEntityConstants.TOKEN_USERGEN);
            endEntityInfo.setType(EndEntityTypes.ENDUSER.toEndEntityType());
            endEntityInfo.setStatus(EndEntityConstants.STATUS_NEW);
            endEntityManagementSession.addUser(ADMIN, endEntityInfo, false);

            final String requestDN = "CN=" + CN + ",O=EJBCA,C=SE";
            PKCS10CertificationRequest p10 = generateCertReq(requestDN, "foo123", null, null, null, ec256);
            byte[] reqmsg = Base64.encode(p10.getEncoded());
            byte[] resp = sendEstRequest(alias, "simpleenroll", reqmsg, 200, null); 
            assertNotNull("There must be response data to simpleenroll request", resp);
            CMSSignedData respmsg = new CMSSignedData(Base64.decode(resp));
            final Store<X509CertificateHolder> certstore = respmsg.getCertificates();
            Collection<X509CertificateHolder> certs = certstore.getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, certs.size());
            X509Certificate testcacert = (X509Certificate)serverCertCaInfo.getCertificateChain().get(0);
            final X509CertificateHolder certHolder = certs.iterator().next();
            X509Certificate cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
            assertEquals("simpleenroll response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(testcacert), CertTools.getIssuerDN(cert));
            try {
                cert.verify(testcacert.getPublicKey());
            } catch (SignatureException e) {
                fail("simpleenroll response certifciate must verify with CA certificate");                
            }
            assertEquals("simpleenroll response subjectDN must be the same DN as the PKCS#10 request DN",requestDN, CertTools.getSubjectDN(cert));
            assertEquals("simpleenroll response public key must be the same as the PKCS#10 request", Base64.toBase64String(ec256.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));            

            //
            // 2. Make EST simplereenroll request, message is a simple PKCS#10 request, RFC7030 section 4.2.2
            //
            // No client certificate should give unauthorized, regardless if we have username/pwd or not
            sendEstRequest(alias, "simplereenroll", reqmsg, 401, "<html><head><title>Error</title></head><body>Can't reenroll without using a TLS client cert</body></html>"); 
            sendEstRequest(alias, "simplereenroll", reqmsg, 401, "<html><head><title>Error</title></head><body>Can't reenroll without using a TLS client cert</body></html>"); 
            // Now try with actual client cert authentication, using a certificate that can be used for client cert auth, i.e. Management CA as we got above
            setupClientKeyStore(serverCertCaInfo, ec256, cert);
            // Not allowing same keys should give an error, this gives today 400 (SC_BAD_REQUEST) but should probably be a 401 instead
            // Log will show: 2021-02-22 11:03:07,822 INFO  [org.ejbca.core.protocol.est.EstOperationsSessionBean] (default task-4) Invalid key. The public key in the KeyUpdateRequest is the same as the public key in the existing end entity certificate: CN=ESTRARAReenroll036018,O=EJBCA,C=SE
            sendEstRequest(true, alias, "simplereenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Exception encountered when performing EST operation 'simplereenroll' on alias 'ESTClientSimpleReEnroll'.</body></html>", 
                    null, null);
            // A new request with new keys, but with the same subject DN should succeed
            final KeyPair ec256New = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
            final PKCS10CertificationRequest p10New = generateCertReq(requestDN, null, null, null, null, ec256New);
            final byte[] reqmsgNew = Base64.encode(p10New.getEncoded());
            resp = sendEstRequest(true, alias, "simplereenroll", reqmsgNew, 200, null, null, null);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            respmsg = new CMSSignedData(Base64.decode(resp));
            certs = respmsg.getCertificates().getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, certs.size());
            testcacert = (X509Certificate)serverCertCaInfo.getCertificateChain().get(0);
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
            resp = sendEstRequest(true, alias, "simplereenroll", reqmsgNew, 200, null, null, null);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            
            // Try again, but now using the new key for TLS authentication as well, not allowing same keys should give an error as above with the new request as well
            setupClientKeyStore(serverCertCaInfo, ec256New, cert);
            sendEstRequest(true, alias, "simplereenroll", reqmsgNew, 400, "<html><head><title>Error</title></head><body>Exception encountered when performing EST operation 'simplereenroll' on alias 'ESTClientSimpleReEnroll'.</body></html>", 
                    null, null);
            // Modify alias to allow same keys
            config.setKurAllowSameKey(alias, true);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            resp =  sendEstRequest(true, alias, "simplereenroll", reqmsgNew, 200, null, null, null);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            respmsg = new CMSSignedData(Base64.decode(resp));
            certs = respmsg.getCertificates().getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, certs.size());

            // If our end entity changes username, it should not matter, as we will find the end entity based on the full request DN
            endEntityManagementSession.renameEndEntity(ADMIN, CN, CN+"Foo");
            resp =  sendEstRequest(true, alias, "simplereenroll", reqmsgNew, 200, null, null, null);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.2.3
            assertNotNull("There must be response data to simpleenroll request", resp);
            respmsg = new CMSSignedData(Base64.decode(resp));
            certs = respmsg.getCertificates().getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, certs.size());

            // Change the subject DN in the CSR, should not be allowed to reenroll now
            // Log will show: 11:11:45,539 INFO  [org.ejbca.core.protocol.est.EstOperationsSessionBean] (default task-4) Can't reenroll using different subject than requesting certificate. Request DN='CN=ESTRARAReenroll204554,OU=Test,O=EJBCA,C=SE'
            final PKCS10CertificationRequest p10NewDN = generateCertReq(requestDN + ",OU=Test", null, null, null, null, ec256New);
            final byte[] reqmsgNewDN = Base64.encode(p10NewDN.getEncoded());
            sendEstRequest(true, alias, "simplereenroll", reqmsgNewDN, 400, "<html><head><title>Error</title></head><body>Exception encountered when performing EST operation 'simplereenroll' on alias 'ESTClientSimpleReEnroll'.</body></html>", 
                    null, null);
        } finally {
            // Remove the certificates
            internalCertStoreSession.removeCertificatesByUsername(CN);
            internalCertStoreSession.removeCertificatesByUsername(CN+"Foo");
            // Remove EST alias
            config.removeAlias(alias);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // Remove end entity
            try {
                endEntityManagementSession.deleteUser(ADMIN, CN);
            } catch (NoSuchEndEntityException e) {} // NOPMD
            try {
                endEntityManagementSession.deleteUser(ADMIN, CN+"Foo");
            } catch (NoSuchEndEntityException e) {} // NOPMD
        }        
        log.trace("<testSimpleReenroll()");
    }

}
