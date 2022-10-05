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
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
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
import org.ejbca.core.model.SecConst;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;
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
 * Tests EST vendor mode. Initial enrollment, using a TLS certificate issued from a "Vendor CA", issuing a certificate from an "Operator CA".
 * There may be a name change between the Vendor certificate and the Operator certificate, or not..
 */
public class EstVendorModeTest extends EstTestCase {

    private static final Logger log = Logger.getLogger(EstVendorModeTest.class);

    private static final String TESTCA_NAME = EstVendorModeTest.class.getSimpleName();
    private static KeyPair ec256client;
    private static boolean isESTEnabled = false; // if EST was enabled or not before running test 
    
    private static final GlobalConfigurationSession globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);

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
        ec256client = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
        
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

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
    
    /**
     * Tests initial enrollment with Vendor certificate authentication.
     * Vendor cert authentication uses a "vendor" client certificate to do TLS authentication with the EST/CA server, who then issues a new 
     * "operator" certificate from a different CA.
     * To authenticate the vendor certificate, an end entity has to be added in EJBCA where the vendor TLS cert is mapped to the end entity
     * using DN extraction (commonly say the serial number of a device as the vendor certs CN, mapping an an EE with username=serial number).
     * The verification of the vendor certificate, mapping to an EE with status=NEW, and verifying against one of the allowed Vendor CAs makes 
     * up the user authentication/authorization for enrollment.
     * The issued operator certificate can have a different subject DN that the vendor TLS certificate, if "name change" is allowed in the EST 
     * configuration, and the CSR contains the ChangeSubjectName extension (RFC7030 section 4.2.2). 
     * 
     * Renewal is a standard reenroll, where the already issued operator certificate now authenticates with TLS, the EE is discovered based on 
     * the full CSR DN (and the CSR DN must be the same as the TLS operator cert DN, no name change allowed here).
     * 
     * What makes the test hard to implement is that we need certificates that can be used for TLS authentication. Therefore the first test
     * issues an Operator certificate from a Test CA, which can not be used with TLS for reenroll, as the Test CA is not added to JBoss's 
     * truststore (because we create the Test CA dynamically as part of this test).
     */
    @Test
    public void testVendorModeEnroll() throws Exception {
        log.trace(">testVendorModeEnroll()");
        final String alias = "ESTVendorModeSimpleEnroll";

        final String VENDOR_USERNAME = "EstVendorModeTest.vendorcert";
        final String TEST_CN = "EstVendorModeTestUser";
        final String changeEndEntityDN = "CN=" + "foo" + ",O=EJBCA,C=SE";
        
        final EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        try {
            // Create EST Alias
            config.addAlias(alias);
            config.setOperationMode(alias, EstConfiguration.OPERATION_MODE_CLIENT);
            config.setVendorMode(alias, true);
            // In order to use vendor mode we need to be able to establish a TLS connection with client authentication, which means
            // that we need a client certificate issued from ManagementCA, which is an accepted CA for TLS client certs
            // We also need to enroll against port 8443
            final CAInfo serverCertCaInfo = CaTestUtils.getServerCertCaInfo(ADMIN);
            config.setVendorCaIds(alias, serverCertCaInfo.getCAId() + ";1337"); // Dummy id just to see that we handle a list
            config.setExtractUsernameComponent(alias, "CN"); 
            config.setKurAllowSameKey(alias, false);
            config.setAllowChangeSubjectName(alias, false);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            
            // 
            // 1. First we need to get a "vendor" certificate issued by the management CA. We'll issue a cert from mgmt CA and delete the
            // cert and end entity from the database, so EJBCA doesn't know about it, i.e. simulating a real vendor cert that is not in 
            // the EJBCA database.
            final KeyPair ec256vendor = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
            final X509Certificate vendorcert;
            final IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
            try {
                final String vendorpwd = pwdgen.getNewPassword(16, 16);
                final EndEntityInformation endEntityInformation = new EndEntityInformation();
                endEntityInformation.setUsername(VENDOR_USERNAME);
                endEntityInformation.setPassword(vendorpwd);
                endEntityInformation.setDN("CN="+VENDOR_USERNAME + ", O=Vendor, C=ES");
                endEntityInformation.setCAId(serverCertCaInfo.getCAId());
                endEntityInformation.setEmail(null);
                endEntityInformation.setSubjectAltName(null);
                endEntityInformation.setStatus(EndEntityConstants.STATUS_NEW);
                endEntityInformation.setTokenType(SecConst.TOKEN_SOFT_JKS);
                endEntityInformation.setEndEntityProfileId(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
                endEntityInformation.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
                endEntityInformation.setType(new EndEntityType(EndEntityTypes.ENDUSER, EndEntityTypes.ADMINISTRATOR));
                // Remove end entity
                if (endEntityManagementSession.existsUser(VENDOR_USERNAME)) {
                    try {
                        endEntityManagementSession.deleteUser(ADMIN, VENDOR_USERNAME);
                    } catch (NoSuchEndEntityException e) {} // NOPMD
                }
                log.info("Adding new user for vendor certificate: " + endEntityInformation.getUsername());
                endEntityManagementSession.addUser(ADMIN, endEntityInformation, true);
                // Generate the vendor certificate
                final RequestMessage req = new SimpleRequestMessage(ec256vendor.getPublic(), VENDOR_USERNAME, vendorpwd);
                final X509ResponseMessage responseMessage = (X509ResponseMessage) certificateCreateSession.createCertificate(ADMIN, endEntityInformation, req, X509ResponseMessage.class, new CertificateGenerationParams());
                vendorcert = (X509Certificate)responseMessage.getCertificate();
            } finally {
                // Remove the certificates generated
                internalCertStoreSession.removeCertificatesByUsername(VENDOR_USERNAME);
                // Remove end entity
                try {
                    log.info("Removing user for vendor certificate: " + VENDOR_USERNAME);
                    endEntityManagementSession.deleteUser(ADMIN, VENDOR_USERNAME);
                } catch (NoSuchEndEntityException e) {} // NOPMD
            }

            //
            // 2. Issue a first certificate with a EST simpleenroll request, message is a simple PKCS#10 request, RFC7030 section 4.2.1
            // Authentication is TLS with the vendor certificate created above
            // 
            // First with no EE created, should fail, with or without client cert authentication
            String requestDN = "CN=" + TEST_CN + ",O=EJBCA,C=SE";
            final String clientpwd = pwdgen.getNewPassword(16, 16);
            PKCS10CertificationRequest p10 = generateCertReq(requestDN, clientpwd, null, null, null, ec256client);
            byte[] reqmsg = Base64.encode(p10.getEncoded());
            sendEstRequest(alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Invalid username, enrollment code, or end entity status</body></html>"); 
            // Now try with actual client cert authentication, using a certificate that can be used for client cert auth, i.e. Management CA as we got above
            setupClientKeyStore(serverCertCaInfo, ec256vendor, vendorcert);
            sendEstRequest(true, alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Invalid username, enrollment code, or end entity status</body></html>", 
                    null, null);
            sendEstRequest(true, alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Invalid username, enrollment code, or end entity status</body></html>", 
                    TEST_CN, clientpwd);

            // Second create an EE so we can issue the cert, but create EE with wrong username to start with
            String requestAltName = "rfc822name=foo@bar.com";
            EndEntityInformation endEntityInfo = new EndEntityInformation();
            endEntityInfo.setUsername(TEST_CN); // should be CN of vendor cert in order to function, so this will fail
             // This password should not be used for anything, it's vendor cert authentication, not password auth
            final String clientpwd2 = pwdgen.getNewPassword(16, 16);
            endEntityInfo.setPassword(clientpwd2); 
            endEntityInfo.setEndEntityProfileId(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            endEntityInfo.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            endEntityInfo.setCAId(serverCertCaInfo.getCAId());
            endEntityInfo.setDN(requestDN);
            endEntityInfo.setTokenType(EndEntityConstants.TOKEN_USERGEN);
            endEntityInfo.setType(new EndEntityType(EndEntityTypes.ENDUSER, EndEntityTypes.ADMINISTRATOR));
            endEntityInfo.setStatus(EndEntityConstants.STATUS_NEW);
            endEntityManagementSession.addUser(ADMIN, endEntityInfo, false);
            
            // No client certificate should give unauthorized, regardless if we have username/pwd or not
            p10 = generateCertReq(requestDN, clientpwd, null, null, null, ec256client);
            reqmsg = Base64.encode(p10.getEncoded());
            sendEstRequest(alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Invalid username, enrollment code, or end entity status</body></html>"); 
            p10 = generateCertReq(requestDN, clientpwd, null, null, null, ec256client);
            reqmsg = Base64.encode(p10.getEncoded());
            sendEstRequest(alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Invalid username, enrollment code, or end entity status</body></html>");

            // Now try with actual client cert authentication, using a certificate that can be used for client cert auth, i.e. Management CA as we got above
            setupClientKeyStore(serverCertCaInfo, ec256vendor, vendorcert);

            // USe a request without password now
            p10 = generateCertReq(requestDN, null, null, null, null, ec256client);
            reqmsg = Base64.encode(p10.getEncoded());
            
            // Still we have the wrong username in the EE though, the username should match the Vendor TLS cert, and not the P10 requestDN
            sendEstRequest(true, alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Invalid username, enrollment code, or end entity status</body></html>", null, null);
            
            // Set the right DN now, matching the TLS vendor certificate (CN as we use CN as extract username component)
            endEntityInfo.setUsername(VENDOR_USERNAME); // should be CN of vendor cert in order to function
            
            endEntityManagementSession.deleteUser(ADMIN, TEST_CN); // we don't need this, we just wanted to check that there was no accidental mapping
            endEntityManagementSession.addUser(ADMIN, endEntityInfo, false);
                    
            // Since we use a different request DN from vendor DN here, we should not allow this with or without allow ChangeSubjectName attribute
            sendEstRequest(true, alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Can't enroll using different subject than requesting certificate. Request DN='CN=EstVendorModeTestUser,O=EJBCA,C=SE'</body></html>", null, null);
            
            // Now we allow ChangeSubjectName in alias, but DN in request still don't match the cert used for authentication
            config.setAllowChangeSubjectName(alias, true);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            sendEstRequest(true, alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Can't enroll using different subject than requesting certificate. Request DN='CN=EstVendorModeTestUser,O=EJBCA,C=SE'</body></html>", null, null);
            
            // We change the DN in the request to match the authentication certificate
            requestDN = "CN=" + VENDOR_USERNAME + ",O=Vendor,C=ES";//Request and tls must be the same DN
            p10 = generateCertReq(requestDN, null, requestDN, null, null, ec256client);
            reqmsg = Base64.encode(p10.getEncoded());
            // We use ChangeSubjectName attribute in CSR, but it must match the end entity and since they don't we should fail
            sendEstRequest(true, alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>ChangeSubjectName requested but End Entity DN is 'CN=EstVendorModeTestUser,O=EJBCA,C=SE' and ChangeSubjectName is 'CN=EstVendorModeTest.vendorcert,O=Vendor,C=ES'.</body></html>", null, null);
            
            //Now, we create a new request and configure the end entity to match a ChangeSubjectName attribute that also differs from the requestDN... 
            // given
            endEntityInfo.setDN(changeEndEntityDN);
            endEntityInfo.setSubjectAltName(requestAltName);
            endEntityManagementSession.deleteUser(ADMIN, VENDOR_USERNAME); // we don't need this, we just wanted to check that there was no accidental mapping
            endEntityManagementSession.addUser(ADMIN, endEntityInfo, false);
            // In this request, we want both a new subjectDN and a new altName 
            p10 = generateCertReq(requestDN, null, changeEndEntityDN, requestAltName, null, ec256client);
            reqmsg = Base64.encode(p10.getEncoded());
            // when
            byte[] resp = sendEstRequest(true, alias, "simpleenroll", reqmsg, 200, null, null, null);
            // then
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
            assertEquals("simpleenroll response subjectDN must be the same DN as the ChangeSubjectName attribute DN", changeEndEntityDN, CertTools.getSubjectDN(cert));
            assertEquals("simpleenroll response subjectAltName must be the same as the ChangeSubjectName attribute subjectAlName", "rfc822name=foo@bar.com", CertTools.getSubjectAlternativeName(cert));
            assertEquals("simpleenroll response public key must be the same as the PKCS#10 request", Base64.toBase64String(ec256client.getPublic().getEncoded()), Base64.toBase64String(cert.getPublicKey().getEncoded()));
                       
            //We also want to make a request with only a subjectAltName in the ChangeSubjectName attribute.
            // given
            p10 = generateCertReq(requestDN, null, null, requestAltName, null, ec256client);
            reqmsg = Base64.encode(p10.getEncoded());
            endEntityManagementSession.setUserStatus(ADMIN, VENDOR_USERNAME, EndEntityConstants.STATUS_NEW );
            // when    
            byte[] onlySANresp = sendEstRequest(true, alias, "simpleenroll", reqmsg, 200, null, null, null);
            // then
            assertNotNull("There must be response data to simpleenroll request", onlySANresp);
            CMSSignedData onlySANrespmsg = new CMSSignedData(Base64.decode(onlySANresp));
            final Store<X509CertificateHolder> onlySANcertstore = onlySANrespmsg.getCertificates();
            Collection<X509CertificateHolder> onlySANcerts = onlySANcertstore.getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, onlySANcerts.size());
            X509Certificate onlySANtestcacert = (X509Certificate)serverCertCaInfo.getCertificateChain().get(0);
            final X509CertificateHolder onlySANcertHolder = onlySANcerts.iterator().next();
            X509Certificate onlySANcert = CertTools.getCertfromByteArray(onlySANcertHolder.getEncoded(), X509Certificate.class);
            assertEquals("simpleenroll response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(onlySANtestcacert), CertTools.getIssuerDN(onlySANcert));
            try {
                onlySANcert.verify(onlySANtestcacert.getPublicKey());
            } catch (SignatureException e) {
                fail("simpleenroll response certifciate must verify with CA certificate");                
            }
            assertEquals("simpleenroll response subjectAltName must be the same as the ChangeSubjectName attribute subjectAlName", "rfc822name=foo@bar.com", CertTools.getSubjectAlternativeName(onlySANcert));
            assertEquals("simpleenroll response public key must be the same as the PKCS#10 request", Base64.toBase64String(ec256client.getPublic().getEncoded()), Base64.toBase64String(onlySANcert.getPublicKey().getEncoded()));
                        
            //Try with a CSR subjectDN that is matching the authentication cert, but not matching the end entity subjectDN, using no ChangeSubjectName, this should fail
            p10 = generateCertReq(requestDN, null, null, null, null, ec256client);
            reqmsg = Base64.encode(p10.getEncoded());
            endEntityInfo.setDN("CN=" + "foo" + ",O=Vendor,C=ES");
            endEntityManagementSession.deleteUser(ADMIN, VENDOR_USERNAME);
            endEntityManagementSession.addUser(ADMIN, endEntityInfo, false);
            sendEstRequest(true, alias, "simpleenroll", reqmsg, 400, "<html><head><title>Error</title></head><body>Request DN must match end entity DN. Request DN='CN=EstVendorModeTest.vendorcert,O=Vendor,C=ES'</body></html>", null, null);
                        
            //We set the correct DN for the end entity and make request without ChangeSubjectName attribute, this should work
            // given
            endEntityInfo.setDN(requestDN);
            endEntityManagementSession.deleteUser(ADMIN, VENDOR_USERNAME); 
            endEntityManagementSession.addUser(ADMIN, endEntityInfo, false);
            p10 = generateCertReq(requestDN, null, null, null, null, ec256client);
            reqmsg = Base64.encode(p10.getEncoded());
            // when
            byte[] noattributeresp = sendEstRequest(true, alias, "simpleenroll", reqmsg, 200, null, null, null);
            // then
            assertNotNull("There must be response data to simpleenroll request", noattributeresp);
            CMSSignedData noattributerespmsg = new CMSSignedData(Base64.decode(noattributeresp));
            final Store<X509CertificateHolder> noattributecertstore = noattributerespmsg.getCertificates();
            Collection<X509CertificateHolder> noattributecerts = noattributecertstore.getMatches(null);
            assertEquals("EST simpleenroll should return a single certificate", 1, noattributecerts.size());
            X509Certificate noattributetestcacert = (X509Certificate)serverCertCaInfo.getCertificateChain().get(0);
            final X509CertificateHolder noattributecertHolder = noattributecerts.iterator().next();
            X509Certificate noattributecert = CertTools.getCertfromByteArray(noattributecertHolder.getEncoded(), X509Certificate.class);
            assertEquals("simpleenroll response issuerDN must be our EST test CAs subjectDN", CertTools.getSubjectDN(noattributetestcacert), CertTools.getIssuerDN(noattributecert));
            assertEquals("simpleenroll response subjectDN must be the same DN as the CSR request DN", requestDN, CertTools.getSubjectDN(noattributecert));
            
            // something we can not test here is re-enroll, as the newly issued "operator" certificate is not valid for TLS connections
            // we test re-enroll in both RA and client mode however, and it should work the same
            // In client mode we test reenroll with chaning username, which reflects when the ChangeName is used and we create
            // an end entity with the username=CN of Vendor Cert, but issue an operator cert with another CN
        } finally {
            // Remove the certificates
            internalCertStoreSession.removeCertificatesByUsername(TEST_CN);
            internalCertStoreSession.removeCertificatesByUsername(VENDOR_USERNAME);
            // Remove EST alias
            config.removeAlias(alias);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // Remove end entities
            try {
                endEntityManagementSession.deleteUser(ADMIN, TEST_CN);
            } catch (NoSuchEndEntityException e) {} // NOPMD
            try {
                endEntityManagementSession.deleteUser(ADMIN, VENDOR_USERNAME);
            } catch (NoSuchEndEntityException e) {} // NOPMD
        }        
        log.trace("<testVendorModeEnroll()");
    }
}