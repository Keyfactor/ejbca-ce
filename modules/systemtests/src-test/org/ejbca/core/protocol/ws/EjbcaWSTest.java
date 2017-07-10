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
package org.ejbca.core.protocol.ws;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.TimeZone;

import javax.ejb.RemoveException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.CaTestUtils;
import org.cesecore.ErrorCode;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.validation.KeyValidationFailedActions;
import org.cesecore.keys.validation.KeyValidatorProxySessionRemote;
import org.cesecore.keys.validation.KeyValidatorSessionTest;
import org.cesecore.keys.validation.KeyValidatorSettingsTemplate;
import org.cesecore.keys.validation.RsaKeyValidator;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.Base64;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.ejb.ws.EjbcaWSHelperSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalTest;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.hardtoken.HardTokenConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.ws.client.gen.AlreadyRevokedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.HardTokenDataWS;
import org.ejbca.core.protocol.ws.client.gen.IllegalQueryException_Exception;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.KeyValuePair;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.core.protocol.ws.client.gen.NotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.PinDataWS;
import org.ejbca.core.protocol.ws.client.gen.RevokeStatus;
import org.ejbca.core.protocol.ws.client.gen.TokenCertificateRequestWS;
import org.ejbca.core.protocol.ws.client.gen.TokenCertificateResponseWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * This test uses remote EJB calls to setup the environment.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EjbcaWSTest extends CommonEjbcaWS {

    private static final Logger log = Logger.getLogger(EjbcaWSTest.class);

    public final static String WS_ADMIN_ROLENAME = "WsTEstRole";
    public final static String WS_TEST_ROLENAME = "WsTestRoleMgmt";
    private final static String WS_TEST_CERTIFICATE_PROFILE_NAME = "WSTESTPROFILE"; 
    private static final String KEY_RECOVERY_EEP = "KEYRECOVERY";
    
    private final ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
    private final CAAdminSessionRemote caAdminSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final EjbcaWSHelperSessionRemote ejbcaWSHelperSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EjbcaWSHelperSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final HardTokenSessionRemote hardTokenSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(HardTokenSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final KeyValidatorProxySessionRemote keyValidatorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyValidatorProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private static String originalForbiddenChars;
    private final static SecureRandom secureRandom;
    private final static String forbiddenCharsKey = "forbidden.characters";
    static {
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<File> fileHandles = new ArrayList<>();
    
    private GlobalConfiguration originalGlobalConfiguration = null;

    @BeforeClass
    public static void beforeClass() throws Exception {
        adminBeforeClass();
        fileHandles = setupAccessRights(WS_ADMIN_ROLENAME);
        CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
                CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        originalForbiddenChars = cesecoreConfigurationProxySession.getConfigurationValue(forbiddenCharsKey);
    }

    @Before
    public void setUpAdmin() throws Exception {
        adminSetUpAdmin();
        originalGlobalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        cleanUpAdmins(WS_ADMIN_ROLENAME);
        cleanUpAdmins(WS_TEST_ROLENAME);
        CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
                CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        cesecoreConfigurationProxySession.setConfigurationValue(forbiddenCharsKey, originalForbiddenChars);
        CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
        certificateProfileSession.removeCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME);
        for (File file : fileHandles) {
            FileTools.delete(file);
        }
    }

    @Override
    public String getRoleName() {
        return WS_TEST_ROLENAME;
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        // Restore WS admin access
        setAccessRulesForWsAdmin(Arrays.asList(StandardRules.ROLE_ROOT.resource()), null);
        // Restore key recovery, end entity profile limitations etc
        if (originalGlobalConfiguration!=null) {
            globalConfigurationSession.saveConfiguration(intAdmin, originalGlobalConfiguration);
        }
    }

    private void setAccessRulesForWsAdmin(final List<String> resourcesAllowed, final List<String> resourcesDenied) throws AuthorizationDeniedException {
        final Role role = roleSession.getRole(intAdmin, null, WS_ADMIN_ROLENAME);
        assertNotNull("Role " + WS_ADMIN_ROLENAME + " does not exist!", role);
        role.getAccessRules().clear();
        if (resourcesAllowed!=null) {
            for (final String resource : resourcesAllowed) {
                role.getAccessRules().put(resource, Role.STATE_ALLOW);
            }
        }
        if (resourcesDenied!=null) {
            for (final String resource : resourcesDenied) {
                role.getAccessRules().put(resource, Role.STATE_DENY);
            }
        }
    }

    /** This test is not a WebService test, but for simplicity it re-uses the created administrator certificate in order to connect to the
     * EJBCA Admin Web and verify returned security headers.
     * @throws IOException 
     * @throws CertificateException 
     * @throws KeyStoreException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyManagementException 
     * @throws UnrecoverableKeyException 
     */
    @Test
    public void testAdminWebSecurityHeaders() throws UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        HttpURLConnection con = super.getHttpsURLConnection("https://" + hostname + ":" + httpsPort + "/ejbca/adminweb/index.jsp");
        String xframe = con.getHeaderField("X-FRAME-OPTIONS");
        String csp = con.getHeaderField("content-security-policy");
        String xcsp = con.getHeaderField("x-content-security-policy");
        con.disconnect();
        assertNotNull("Admin web page should return X-FRAME-OPTIONS header", xframe);
        assertNotNull("Admin web page should return content-security-policy header", csp);
        assertNotNull("Admin web page should return x-content-security-policy header", xcsp);
        assertEquals("Admin web page should return X-FRAME-OPTIONS SAMEORIGIN", "SAMEORIGIN", xframe);
        assertEquals("Admin web page should return csp default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self'; frame-src 'self'; form-action 'self'; plugin-types application/pdf; reflected-xss block", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self'; frame-src 'self'; connect-src 'self'; form-action 'self'; reflected-xss block", csp);
        assertEquals("Admin web page should return xcsp default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self'; frame-src 'self'; form-action 'self'; plugin-types application/pdf; reflected-xss block", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self'; frame-src 'self'; connect-src 'self'; form-action 'self'; reflected-xss block", xcsp);
    }

    @Test
    public void testCaRolloverCommands() throws Exception {
        final String rootCaName ="RollOverRootCA";
        final String rootCaDn = "CN="+rootCaName;
        final String subCaName = "RollOverSubCA";
        final String subCaSubjectDn = "CN=" + subCaName;
        X509CA subCA = null;
        X509CA rootCA = null;
        try {
            //rootCA a rootCA
            rootCA = CaTestUtils.createTestX509CA(rootCaDn, PASSWORD.toCharArray(), false);
            CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
            caSession.addCA(intAdmin, rootCA);
            X509Certificate cacert = (X509Certificate) rootCA.getCACertificate();
            certificateStoreSession.storeCertificateRemote(intAdmin, EJBTools.wrap(cacert), "testuser", "1234",  CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ROOTCA, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityInformation.NO_ENDENTITYPROFILE, null, new Date().getTime());
            //Create a SubCA for this test. 
            subCA = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(intAdmin, subCaSubjectDn, rootCA.getCAId());
            int cryptoTokenId = subCA.getCAToken().getCryptoTokenId();
            cryptoTokenManagementSession.createKeyPair(intAdmin, cryptoTokenId, "signKeyAlias", "1024");
            X509Certificate subCaCertificate = (X509Certificate) subCA.getCACertificate();
            //Store the CA Certificate.
            certificateStoreSession.storeCertificateRemote(intAdmin, EJBTools.wrap(subCaCertificate), "foo", "1234", CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_SUBCA, CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, EndEntityInformation.NO_ENDENTITYPROFILE, "footag", new Date().getTime());
            final EndEntityInformation endentity = new EndEntityInformation(subCaName, subCaSubjectDn, rootCA.getCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.TOKEN_USERGEN, 0, null);
            endentity.setStatus(EndEntityConstants.STATUS_NEW);
            endentity.setPassword("foo123");
            final ExtendedInformation ei = new ExtendedInformation();
            long rolloverStartTime = System.currentTimeMillis()+7L*24L*3600L*1000L;

            ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, ValidityDate.formatAsUTC(rolloverStartTime));
            ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, ValidityDate.formatAsUTC(rolloverStartTime+14L*24L*3600L*1000L));
            endentity.setExtendedinformation(ei);
            
            //Make sure there is a rollover certificate in store
            final byte[] requestbytes = caAdminSessionRemote.makeRequest(intAdmin, subCA.getCAId(), null, null);
            final PKCS10RequestMessage req = new PKCS10RequestMessage(requestbytes);
            final X509ResponseMessage respmsg = (X509ResponseMessage) certificateCreateSession.createCertificate(intAdmin, endentity, req, X509ResponseMessage.class, null);
            X509Certificate newCertificate =  (X509Certificate) respmsg.getCertificate();
            ejbcaraws.caCertResponseForRollover(subCaName, newCertificate.getEncoded(), null, "foo123");

            //Check that sub CA has a rollover certificate 
            Certificate rolloverCertificate = caSession.getFutureRolloverCertificate(subCA.getCAId());
            assertNotNull("No rollover certificate was found in subCA", rolloverCertificate);
            X509CAInfo subCAInfo = (X509CAInfo) caSession.getCAInfo(intAdmin, subCA.getCAId());
            assertFalse("CA was unintentionally rolled over.", subCAInfo.getCertificateChain().iterator().next().equals(rolloverCertificate));
            //Perform the rollover
            ejbcaraws.rolloverCACert(subCaName);
            subCAInfo = (X509CAInfo) caSession.getCAInfo(intAdmin, subCA.getCAId());
            assertTrue("CA was not rolled over.", subCAInfo.getCertificateChain().iterator().next().equals(rolloverCertificate));
            
        } finally {
            if (subCA != null) {
                CaTestUtils.removeCa(intAdmin, subCA.getCAInfo());
            }
            if(rootCA != null) {
                CaTestUtils.removeCa(intAdmin, rootCA.getCAInfo());
            }
            internalCertificateStoreSession.removeCertificatesBySubject(subCaSubjectDn);
            internalCertificateStoreSession.removeCertificatesBySubject(rootCaDn);

        }
    }
    
    @Test
    public void test01EditUser() throws Exception {
        super.editUser();
    }

    @Test
    public void test02FindUser() throws Exception {
        findUser();
    }

    @Test
    public void test03_1GeneratePkcs10WithBlacklistedKey() throws Exception {
        generatePkcs10(true);
    }

    @Test
    public void test03_2GenerateCrmfNoPop() throws Exception {
        generateCrmf(false, false, false);
    }
    @Test
    public void test03_2GenerateCrmfPopSign() throws Exception {
        generateCrmf(true, false, false);
    }
    @Test
    public void test03_2GenerateCrmfPopSignPkMac() throws Exception {
        generateCrmf(true, true, false);
    }
    @Test
    public void test03_2GenerateCrmfPopSignSender() throws Exception {
        generateCrmf(true, false, true);
    }

    @Test
    public void test03_3GenerateSpkac() throws Exception {
        generateSpkac();
    }

    @Test
    public void test03_4GeneratePkcs10Request() throws Exception {
        generatePkcs10Request();
    }

    @Test
    public void test03_5CertificateRequest() throws Exception {
        certificateRequest();
    }

    @Test
    public void test03_6EnforcementOfUniquePublicKeys() throws Exception {
        enforcementOfUniquePublicKeys();
    }

    @Test
    public void test03_6EnforcementOfUniqueSubjectDN() throws Exception {
        enforcementOfUniqueSubjectDN();
    }

    @Test
    public void test03_7ThrowAwayConfiguration() throws Exception {
        certificateRequestThrowAway();
    }
    
    @Test
    public void test03_8DontStoreFullCert() throws Exception {
        certificateRequestDontStoreFullCert();
    }
    
    @Test
    public void test03_9CertificateRequestBadParameters() throws Exception {
        final UserDataVOWS userDataVOWS = new UserDataVOWS();
        userDataVOWS.setCaName("EjbcaWSTest_NonexistentCA");
        userDataVOWS.setEndEntityProfileName("EjbcaWSTest_NonexistentEEProfile");
        userDataVOWS.setEndEntityProfileName("EjbcaWSTest_NonexistentCertProfile");
        
        try {
            ejbcaraws.certificateRequest(userDataVOWS, "junk", CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
            fail("Should have failed because CA is missing");
        } catch (EjbcaException_Exception e) {
            assertEquals(e.getFaultInfo().getErrorCode().getInternalErrorCode(), ErrorCode.CA_NOT_EXISTS.getInternalErrorCode());
        }
        userDataVOWS.setCaName(CA1);
        userDataVOWS.setEndEntityProfileName(WS_EEPROF_EI);
        try {
            ejbcaraws.certificateRequest(userDataVOWS, "junk", CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
            fail("Should have failed because no certificate profile is set");
        } catch (EjbcaException_Exception e) {
            assertEquals(e.getFaultInfo().getErrorCode().getInternalErrorCode(), ErrorCode.CERT_PROFILE_NOT_EXISTS.getInternalErrorCode());
        }
        userDataVOWS.setCertificateProfileName(WS_CERTPROF_EI);
        try {
            ejbcaraws.certificateRequest(userDataVOWS, "junk", CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
            fail("Expected empty username to be rejected according to profile settings.");
        } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
            // NOPMD expected
        }
        userDataVOWS.setUsername("EjbcaWSTestBadUser"); // should never be successfully created, so no cleanup is needed
        userDataVOWS.setSubjectDN("CN=EjbcaWSTestBadUser");
        try {
            ejbcaraws.certificateRequest(userDataVOWS, "junk", CertificateHelper.CERT_REQ_TYPE_PKCS10, null, "xx");
            fail("Should have failed because of invalid RESPONSETYPE value.");
        } catch (EjbcaException_Exception e) {
            assertEquals(e.getFaultInfo().getErrorCode().getInternalErrorCode(), ErrorCode.INTERNAL_ERROR.getInternalErrorCode());
        }
    }

    @Test
    public void test04GeneratePkcs12() throws Exception {
        // A: Generate P12 before key validation. 
        generatePkcs12();
        // B: add RSA key validator with min. key size of 2048 bits -> P12 generation should fail.
        generatePkcs12WithFailedKeyValidation();
    }
    
    private void generatePkcs12WithFailedKeyValidation() throws Exception {
        final UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertNotNull(userdatas);
        assertEquals(1, userdatas.size());
        final String oldTokenType = userdatas.get(0).getTokenType();
        final String oldSubjectDn = userdatas.get(0).getSubjectDN();
        final String oldPassword = userdatas.get(0).getPassword();
        userdatas.get(0).setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        userdatas.get(0).setStatus(EndEntityConstants.STATUS_NEW);
        userdatas.get(0).setSubjectDN(getDN(CA1_WSTESTUSER1));
        userdatas.get(0).setPassword(PASSWORD);
        ejbcaraws.editUser(userdatas.get(0));

        final Integer certificateProfileId = certificateProfileSession.getCertificateProfileId(userdatas.get(0).getCertificateProfileName());
        final String keyValidatorName = "WSPKCS12-RsaKeyValidatorTest";
        final RsaKeyValidator keyValidator = (RsaKeyValidator) KeyValidatorSessionTest.createKeyValidator(RsaKeyValidator.class,
                "WSPKCS12-RsaKeyValidator", keyValidatorName, null, -1, null, -1, KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex(),
                certificateProfileId);
        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
        keyValidator.setBitLengths(RsaKeyValidator.getAvailableBitLengths(2048));
        int keyValidatorId = keyValidatorSession.addKeyValidator(intAdmin, keyValidator);
        
        // Add key validator to CA.
        final CAInfo caInfo = caSession.getCAInfo(intAdmin, CA1);
        final Collection<Integer> keyValidatorIds = new ArrayList<Integer>();
        keyValidatorIds.add(keyValidatorId);
        caInfo.setKeyValidators(keyValidatorIds);
        caSession.editCA(intAdmin, caInfo);
        
        try {
            ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, userdatas.get(0).getPassword(), null, "1024", AlgorithmConstants.KEYALGORITHM_RSA); // generatePkcs12();
            fail("With a RSA key validator and a minimum key size of 2048 bits, the generation of P12 file with a 1024 bit RSA key should fail with an EjbcaException_Exception wrapping a KeyValidationException");
        } catch(Exception e) {
            Assert.assertTrue( "EjbcaException_Exception expected: " + e.getClass().getName(), e instanceof EjbcaException_Exception);
            Assert.assertTrue( "EjbcaException_Exception with failed key validation must have message: " + e.getMessage(), (e.getMessage().startsWith("org.cesecore.keys.validation.KeyValidationException: Key validator WSPKCS12-RsaKeyValidatorTest could not validate sufficient key quality")));            
        }
        
        // Clean up.
        caInfo.setKeyValidators(new ArrayList<Integer>());
        caSession.editCA(intAdmin, caInfo);
        userdatas.get(0).setTokenType(oldTokenType);
        userdatas.get(0).setSubjectDN(oldSubjectDn);
        userdatas.get(0).setPassword(oldPassword);
        ejbcaraws.editUser(userdatas.get(0));
        keyValidatorSession.removeKeyValidator(intAdmin, keyValidatorId);
    }

    @Test
    public void test05FindCerts() throws Exception {
        findCerts();
    }

    @Test
    public void test060RevokeCert() throws Exception {
        revokeCert();
    }

    @Test
    public void test061RevokeCertBackdated() throws Exception {
        revokeCertBackdated();
    }

    @Test
    public void test07RevokeToken() throws Exception {
        revokeToken();
    }

    @Test
    public void test08CheckRevokeStatus() throws Exception {
        checkRevokeStatus();
    }

    @Test
    public void test09Utf8EditUser() throws Exception {
        utf8EditUser();
    }

    @Test
    public void test10GetLastCertChain() throws Exception {
        getLastCertChain();
    }

    @Test
    public void test11RevokeUser() throws Exception {
        revokeUser();
    }

    @Test
    public void test12IsAuthorized() throws Exception {
        // This is a superadmin keystore, improve in the future
        isAuthorized(true);
    }

    @Test
    public void test13genTokenCertificates() throws Exception {
        genTokenCertificates(false);
    }

    @Test
    public void test14getExistsHardToken() throws Exception {
        getExistsHardToken();
    }

    @Test
    public void test15getHardTokenData() throws Exception {
        getHardTokenData("12345678", false);
    }

    @Test
    public void test16getHardTokenDatas() throws Exception {
        getHardTokenDatas();
    }

    @Test
    public void test17CustomLog() throws Exception {
        customLog();
    }

    @Test
    public void test18GetCertificate() throws Exception {
        getCertificate();
    }

    @Test
    public void test19RevocationApprovals() throws Exception {
        log.trace(">test19RevocationApprovals");
        final String APPROVINGADMINNAME = "superadmin";
        final String TOKENSERIALNUMBER = "42424242";
        final String TOKENUSERNAME = "WSTESTTOKENUSER3";
        final String ERRORNOTSENTFORAPPROVAL = "The request was never sent for approval.";
        final String ERRORNOTSUPPORTEDSUCCEEDED = "Reactivation of users is not supported, but succeeded anyway.";

        final String approvalProfileName = this.getClass().getName() + "-NrOfApprovalsProfile";
        
        // Generate random username and CA name
        String randomPostfix = Integer.toString(secureRandom.nextInt(999999));
        String caname = "wsRevocationCA" + randomPostfix;
        String username = "wsRevocationUser" + randomPostfix;
        int cryptoTokenId = 0;
        int caID = -1;
        AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile(approvalProfileName);
        int partitionId = approvalProfile.getStep(AccumulativeApprovalProfile.FIXED_STEP_ID).getPartitions().values().iterator().next().getPartitionIdentifier();
        approvalProfile.setNumberOfApprovalsRequired(1);
        final int approvalProfileId = approvalProfileSession.addApprovalProfile(intAdmin, approvalProfile);
        try {
            
         
            
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(intAdmin, caname, "1024");
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            caID = RevocationApprovalTest.createApprovalCA(intAdmin, caname, ApprovalRequestType.REVOCATION, approvalProfileId, caAdminSessionRemote, caSession, catoken);
            X509Certificate adminCert = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(APPROVINGADMINNAME)).iterator().next();
            Set<X509Certificate> credentials = new HashSet<>();
            credentials.add(adminCert);
            Set<Principal> principals = new HashSet<>();
            principals.add(adminCert.getSubjectX500Principal());
            AuthenticationToken approvingAdmin = simpleAuthenticationProvider.authenticate(new AuthenticationSubject(principals, credentials));
            try {
                X509Certificate cert = createUserAndCert(username, caID);
                String issuerdn = cert.getIssuerDN().toString();
                String serno = cert.getSerialNumber().toString(16);
                // revoke via WS and verify response
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (WaitingForApprovalException_Exception e1) {
                }
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (ApprovalException_Exception e1) {
                }                
                
                RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
                assertNotNull(revokestatus);
                assertTrue(revokestatus.getReason() == RevokedCertInfo.NOT_REVOKED);
                // Approve revocation and verify success
                approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD,
                        ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, caID, approvalProfile, AccumulativeApprovalProfile.FIXED_STEP_ID, partitionId);
                // Try to unrevoke certificate
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.NOT_REVOKED);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (WaitingForApprovalException_Exception e) {
                }
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.NOT_REVOKED);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (ApprovalException_Exception e) {
                }
                // Approve revocation and verify success
                approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.NOT_REVOKED, ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE,
                        caID, approvalProfile, AccumulativeApprovalProfile.FIXED_STEP_ID, partitionId);
                // Revoke user
                try {
                    ejbcaraws.revokeUser(username, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, false);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (WaitingForApprovalException_Exception e) {
                }
                try {
                    ejbcaraws.revokeUser(username, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, false);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (ApprovalException_Exception e) {
                }
                // Approve revocation and verify success
                approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD,
                        ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY, caID, approvalProfile, AccumulativeApprovalProfile.FIXED_STEP_ID, partitionId);
                // Try to reactivate user
                try {
                    ejbcaraws.revokeUser(username, RevokedCertInfo.NOT_REVOKED, false);
                    assertTrue(ERRORNOTSUPPORTEDSUCCEEDED, false);
                } catch (AlreadyRevokedException_Exception e) {
                }
            } finally {
                endEntityManagementSession.deleteUser(intAdmin, username);
            }
            try {
                // Create a hard token issued by this CA
                createHardToken(TOKENUSERNAME, caname, TOKENSERIALNUMBER);
                assertTrue(ejbcaraws.existsHardToken(TOKENSERIALNUMBER));
                // Revoke token
                try {
                    ejbcaraws.revokeToken(TOKENSERIALNUMBER, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (WaitingForApprovalException_Exception e) {
                }
                try {
                    ejbcaraws.revokeToken(TOKENSERIALNUMBER, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (ApprovalException_Exception e) {
                }
                // Approve actions and verify success
                approveRevocation(intAdmin, approvingAdmin, TOKENUSERNAME, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD,
                        ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, caID, 
                        approvalProfile, AccumulativeApprovalProfile.FIXED_STEP_ID, partitionId);
            } finally {
                hardTokenSessionRemote.removeHardToken(intAdmin, TOKENSERIALNUMBER);
            }
        } finally {
            approvalProfileSession.removeApprovalProfile(intAdmin, approvalProfileId);
            // Nuke CA
            try {
                caAdminSessionRemote.revokeCA(intAdmin, caID, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            } finally {
                caSession.removeCA(intAdmin, caID);
                CryptoTokenTestUtils.removeCryptoToken(intAdmin, cryptoTokenId);
            }
        }
        log.trace("<test19RevocationApprovals");
    }

    @Test
    public void test20KeyRecoverNewest() throws Exception {
        log.trace(">keyRecover");
        GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        boolean krenabled = gc.getEnableKeyRecovery();
        if (krenabled == true) {
            gc.setEnableKeyRecovery(false);
            globalConfigurationSession.saveConfiguration(intAdmin, gc);
        }

        boolean trows = false;
        try {
            // This should throw an exception that key recovery is not enabled
            ejbcaraws.keyRecoverNewest(CA1_WSTESTUSER1);
        } catch (EjbcaException_Exception e) {
            trows = true;
            // e.printStackTrace();
            assertEquals(e.getMessage(), "Keyrecovery have to be enabled in the system configuration in order to use this command.");
        }
        assertTrue(trows);

        // Set key recovery enabled
        gc.setEnableKeyRecovery(true);
        globalConfigurationSession.saveConfiguration(intAdmin, gc);

        trows = false;
        try {
            // This should throw an exception that the user does not exist
            ejbcaraws.keyRecoverNewest("sdfjhdiuwerw43768754###");
        } catch (NotFoundException_Exception e) {
            trows = true;
            // e.printStackTrace();
            assertEquals(e.getMessage(), "Wrong username or password");
        }
        assertTrue(trows);

        // Add a new End entity profile, KEYRECOVERY
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COMMONNAME);
        profile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);
        profile.setValue(EndEntityProfile.KEYRECOVERABLE, 0, EndEntityProfile.TRUE);
        profile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);
        profile.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, true);
        profile.setReUseKeyRecoveredCertificate(true);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        endEntityProfileSession.addEndEntityProfile(intAdmin, KEY_RECOVERY_EEP, profile);
        assertTrue("Unable to create KEYRECOVERY end entity profile.", endEntityProfileSession.getEndEntityProfile(KEY_RECOVERY_EEP) != null);

        // Add a new user, set token to P12, status to new and end entity
        // profile to key recovery
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setKeyRecoverable(true);
        user1.setUsername("WSTESTUSERKEYREC1");
        user1.setPassword("foo456");
        user1.setClearPwd(true);
        user1.setSubjectDN("CN=WSTESTUSERKEYREC1");
        user1.setCaName(getAdminCAName());
        user1.setEmail(null);
        user1.setSubjectAltName(null);
        user1.setStatus(EndEntityConstants.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        user1.setEndEntityProfileName(KEY_RECOVERY_EEP);
        user1.setCertificateProfileName("ENDUSER");
        ejbcaraws.editUser(user1);

        KeyStore ksenv = ejbcaraws.pkcs12Req("WSTESTUSERKEYREC1", "foo456", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo456");
        assertNotNull(ks);
        Enumeration<String> en = ks.aliases();
        String alias = en.nextElement();
        if(!ks.isKeyEntry(alias)) {
            alias = en.nextElement();
        }
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        assertEquals("CN=WSTESTUSERKEYREC1", cert.getSubjectDN().toString());
        PrivateKey privK = (PrivateKey) ks.getKey(alias, "foo456".toCharArray());

        // This should work now
        ejbcaraws.keyRecoverNewest("WSTESTUSERKEYREC1");

        // Set status to keyrecovery
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("WSTESTUSERKEYREC1");
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 1);
        userdatas.get(0).setStatus(EndEntityConstants.STATUS_KEYRECOVERY);
        ejbcaraws.editUser(userdatas.get(0));
        // A new PK12 request now should return the same key and certificate
        KeyStore ksenv2 = ejbcaraws.pkcs12Req("WSTESTUSERKEYREC1", "foo456", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        java.security.KeyStore ks2 = KeyStoreHelper.getKeyStore(ksenv2.getKeystoreData(), "PKCS12", "foo456");
        assertNotNull(ks2);
        en = ks2.aliases();
        alias = en.nextElement();
        // You never know in which order the certificates in the KS are returned, it's different between java 6 and 7 for ex 
        if(!ks2.isKeyEntry(alias)) {
            alias = en.nextElement();
        }
        X509Certificate cert2 = (X509Certificate) ks2.getCertificate(alias);
        assertEquals(cert2.getSubjectDN().toString(), "CN=WSTESTUSERKEYREC1");
        PrivateKey privK2 = (PrivateKey) ks2.getKey(alias, "foo456".toCharArray());

        // Compare certificates
        assertEquals(cert.getSerialNumber().toString(16), cert2.getSerialNumber().toString(16));
        // Compare keys
        String key1 = new String(Hex.encode(privK.getEncoded()));
        String key2 = new String(Hex.encode(privK2.getEncoded()));
        assertEquals(key1, key2);
        log.trace("<keyRecover");
    }

    @Test
    public void test20bKeyRecoverAny() throws Exception {
        log.trace(">keyRecoverAny");
        final GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        boolean eelimitation = gc.getEnableEndEntityProfileLimitations();
        boolean keyrecovery = gc.getEnableKeyRecovery();
        if (!gc.getEnableKeyRecovery() || !gc.getEnableEndEntityProfileLimitations()) {
            gc.setEnableKeyRecovery(true);
            gc.setEnableEndEntityProfileLimitations(true);
            globalConfigurationSession.saveConfiguration(intAdmin, gc);
        }
        try {
            // Add a new user, set token to P12, status to new and end entity
            // profile to key recovery
            UserDataVOWS user1 = new UserDataVOWS();
            user1.setKeyRecoverable(true);
            user1.setUsername("WSTESTUSERKEYREC2");
            user1.setPassword("foo456");
            user1.setClearPwd(true);
            user1.setSubjectDN("CN=WSTESTUSERKEYREC2");
            user1.setCaName(getAdminCAName());
            user1.setEmail(null);
            user1.setSubjectAltName(null);
            user1.setStatus(EndEntityConstants.STATUS_NEW);
            user1.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
            user1.setEndEntityProfileName(KEY_RECOVERY_EEP);
            user1.setCertificateProfileName("ENDUSER");
            ejbcaraws.editUser(user1);
            final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
            final int eepId = endEntityProfileSession.getEndEntityProfileId(KEY_RECOVERY_EEP);
            final int caId = caSession.getCAInfo(intAdmin, getAdminCAName()).getCAId();
            // generate 4 certificates
            UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue("WSTESTUSERKEYREC2");
            List<java.security.KeyStore> keyStores = new ArrayList<>();
            for (int i=0; i < 4; i++) {
                List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
                assertTrue(userdatas != null);
                assertTrue(userdatas.size() == 1);
                user1 = userdatas.get(0);
                // Surely not all of these properties need to be set again?
                user1.setKeyRecoverable(true);
                user1.setUsername("WSTESTUSERKEYREC2");
                user1.setPassword("foo456");
                user1.setClearPwd(true);
                user1.setSubjectDN("CN=WSTESTUSERKEYREC2");
                user1.setCaName(getAdminCAName());
                user1.setEmail(null);
                user1.setSubjectAltName(null);
                user1.setStatus(EndEntityConstants.STATUS_NEW);
                user1.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
                user1.setEndEntityProfileName(KEY_RECOVERY_EEP);
                user1.setCertificateProfileName("ENDUSER");
                setAccessRulesForWsAdmin(Arrays.asList(StandardRules.ROLE_ROOT.resource()), null);
                ejbcaraws.editUser(user1);
                setAccessRulesForWsAdmin(Arrays.asList(
                        AccessRulesConstants.ROLE_ADMINISTRATOR,
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.VIEW_END_ENTITY,
                        StandardRules.CAACCESS.resource() + caId,
                        AccessRulesConstants.REGULAR_CREATECERTIFICATE,
                        AccessRulesConstants.REGULAR_VIEWENDENTITY,
                        // Additionally we need to have edit rights to clear the password, since this is currently not implicitly granted for non-key recovery
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.EDIT_END_ENTITY,
                        AccessRulesConstants.REGULAR_EDITENDENTITY,
                        // Additionally we need to have access to key recovery in this special case
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.KEYRECOVERY_RIGHTS,
                        AccessRulesConstants.REGULAR_KEYRECOVERY
                        ), null);
                KeyStore ksenv = ejbcaraws.pkcs12Req("WSTESTUSERKEYREC2", "foo456", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
                java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo456");
                assertNotNull(ks);
                keyStores.add(ks);
            }
            // user should have 4 certificates
            assertTrue(keyStores.size() == 4);
            // recover all keys
            for (final java.security.KeyStore ks : keyStores){
                Enumeration<String> en = ks.aliases();
                String alias = en.nextElement();
                // You never know in which order the certificates in the KS are returned, it's different between java 6 and 7 for ex 
                if(!ks.isKeyEntry(alias)) {
                    alias = en.nextElement();
                }
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                assertEquals(cert.getSubjectDN().toString(), "CN=WSTESTUSERKEYREC2");
                PrivateKey privK = (PrivateKey) ks.getKey(alias, "foo456".toCharArray());
                log.info("recovering key. sn "+ cert.getSerialNumber().toString(16) + " issuer "+ cert.getIssuerDN().toString());
                // recover key
                setAccessRulesForWsAdmin(Arrays.asList(
                        AccessRulesConstants.ROLE_ADMINISTRATOR,
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.KEYRECOVERY_RIGHTS,
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.VIEW_END_ENTITY,
                        StandardRules.CAACCESS.resource() + caId,
                        AccessRulesConstants.REGULAR_VIEWCERTIFICATE,
                        AccessRulesConstants.REGULAR_KEYRECOVERY,
                        AccessRulesConstants.REGULAR_VIEWENDENTITY
                        ), null);
                ejbcaraws.keyRecover("WSTESTUSERKEYREC2",cert.getSerialNumber().toString(16),cert.getIssuerDN().toString());
                assertEquals("EjbcaWS.keyRecover failed to set status for end entity.", EndEntityConstants.STATUS_KEYRECOVERY, endEntityAccessSession.findUser(intAdmin, "WSTESTUSERKEYREC2").getStatus());
                // A new PK12 request now should return the same key and certificate
                setAccessRulesForWsAdmin(Arrays.asList(
                        AccessRulesConstants.ROLE_ADMINISTRATOR,
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.VIEW_END_ENTITY,
                        StandardRules.CAACCESS.resource() + caId,
                        AccessRulesConstants.REGULAR_CREATECERTIFICATE,
                        AccessRulesConstants.REGULAR_VIEWENDENTITY,
                        // Additionally we need to have access to key recovery in this special case
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.KEYRECOVERY_RIGHTS,
                        AccessRulesConstants.REGULAR_KEYRECOVERY
                        ), null);
                KeyStore ksenv = ejbcaraws.pkcs12Req("WSTESTUSERKEYREC2", "foo456", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
                java.security.KeyStore ks2 = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo456");
                assertNotNull(ks2);
                en = ks2.aliases();
                alias = en.nextElement();
                // You never know in which order the certificates in the KS are returned, it's different between java 6 and 7 for ex 
                if(!ks.isKeyEntry(alias)) {
                    alias = en.nextElement();
                }
                X509Certificate cert2 = (X509Certificate) ks2.getCertificate(alias);
                assertEquals(cert2.getSubjectDN().toString(), "CN=WSTESTUSERKEYREC2");
                PrivateKey privK2 = (PrivateKey) ks2.getKey(alias, "foo456".toCharArray());
                // Compare certificates
                assertEquals(cert.getSerialNumber().toString(16), cert2.getSerialNumber().toString(16));
                // Compare keys
                String key1 = new String(Hex.encode(privK.getEncoded()));
                String key2 = new String(Hex.encode(privK2.getEncoded()));
                assertEquals(key1, key2);
            }
        } finally {
            gc.setEnableEndEntityProfileLimitations(eelimitation);
            gc.setEnableKeyRecovery(keyrecovery);
            globalConfigurationSession.saveConfiguration(intAdmin, gc);
        }

        log.trace("<keyRecoverAny");
    }
    
    @Test
    public void test21GetAvailableCAs() throws Exception {
        log.trace(">getAvailableCAs");
        Collection<Integer> ids = caSession.getAuthorizedCaIds(intAdmin);
        List<NameAndId> cas = ejbcaraws.getAvailableCAs();
        assertNotNull(cas);
        assertEquals(cas.size(), ids.size());
        boolean found = false;
        for (NameAndId n : cas) {
            if (n.getName().equals(getAdminCAName())) {
                found = true;
            }
        }
        assertTrue(found);
        log.trace("<getAvailableCAs");
    }

    @Test
    public void test22GetAuthorizedEndEntityProfiles() throws Exception {
        log.trace(">getAuthorizedEndEntityProfiles");
        Collection<Integer> ids = endEntityProfileSession.getAuthorizedEndEntityProfileIds(intAdmin, AccessRulesConstants.CREATE_END_ENTITY);
        List<NameAndId> profs = ejbcaraws.getAuthorizedEndEntityProfiles();
        assertNotNull(profs);
        assertEquals(profs.size(), ids.size());
        boolean foundkeyrec = false;
        for (NameAndId nameAndId : profs) {
            log.info("name: " + nameAndId.getName());
            if (nameAndId.getName().equals(KEY_RECOVERY_EEP)) {
                foundkeyrec = true;
            }
            boolean found = false;
            for (Integer i : ids) {
                // All ids must be in profs
                if (nameAndId.getId() == i) {
                    found = true;
                }
            }
            assertTrue("Unable to find profile '" + nameAndId.getName() + "' among authorized EEPs reported by Remote EJB call.", found);
        }
        assertTrue("Could not find " + KEY_RECOVERY_EEP + " end entity profile among authorized profiles.", foundkeyrec);
        log.trace("<getAuthorizedEndEntityProfiles");    
    }

    @Test
    public void test23GetAvailableCertificateProfiles() throws Exception {
        getAvailableCertificateProfiles();
    }

    @Test
    public void test24GetAvailableCAsInProfile() throws Exception {
        getAvailableCAsInProfile();
    }
    
    @Test
    public void test25CreateandGetCRL() throws Exception {
        createAndGetCRL();
    }
    
    @Test
    public void test27EjbcaVersion() throws Exception {
        ejbcaVersion();
    }

    @Test
    public void test29ErrorOnEditUser() throws Exception {
        errorOnEditUser();
    }

    @Test
    public void test30ErrorOnGeneratePkcs10() throws Exception {
        errorOnGeneratePkcs10();
    }

    @Test
    public void test31ErrorOnGeneratePkcs12() throws Exception {
        errorOnGeneratePkcs12();
    }

    @Test
    public void test32OperationOnNonexistingCA() throws Exception {
        operationOnNonexistingCA();
    }

    @Test
    public void test33CheckQueueLength() throws Exception {
        checkQueueLength();
    }

    /** In EJBCA 4.0.0 we changed the date format to ISO 8601. This verifies the that we still accept old requests, but returns UserDataVOWS objects using the new DateFormat 
     * @throws AuthorizationDeniedException */
    @Test
    public void test36EjbcaWsHelperTimeFormatConversion() throws ClassCastException, EjbcaException, AuthorizationDeniedException {
        log.trace(">test36EjbcaWsHelperTimeFormatConversion()");
        final Date nowWithOutSeconds = new Date((new Date().getTime()/60000)*60000);    // To avoid false negatives.. we will loose precision when we convert back and forth..
        final String oldTimeFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US).format(nowWithOutSeconds);
        final String newTimeFormatStorage = FastDateFormat.getInstance("yyyy-MM-dd HH:mm", TimeZone.getTimeZone("UTC")).format(nowWithOutSeconds);
        final String newTimeFormatRequest = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZZ", TimeZone.getTimeZone("CEST")).format(nowWithOutSeconds);
        final String newTimeFormatResponse = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZZ", TimeZone.getTimeZone("UTC")).format(nowWithOutSeconds);
        final String relativeTimeFormat = "0123:12:31";
        log.debug("oldTimeFormat=" + oldTimeFormat);
        log.debug("newTimeFormatStorage=" + newTimeFormatStorage);
        log.debug("newTimeFormatRequest=" + newTimeFormatRequest);
        // Convert from UserDataVOWS with US Locale DateFormat to endEntityInformation
        final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs = new org.ejbca.core.protocol.ws.objects.UserDataVOWS("username", "password", false, "CN=User U", "CA1", null, null, 10, "P12", "EMPTY", "ENDUSER", null);
        userDataVoWs.setStartTime(oldTimeFormat);
        userDataVoWs.setEndTime(oldTimeFormat);
        final EndEntityInformation endEntityInformation1 = ejbcaWSHelperSession.convertUserDataVOWS(userDataVoWs, 1, 2, 3, 4, 5);
        assertEquals("CUSTOM_STARTTIME in old format was not correctly handled (VOWS to VO).", newTimeFormatStorage, endEntityInformation1.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
        assertEquals("CUSTOM_ENDTIME in old format was not correctly handled (VOWS to VO).", newTimeFormatStorage, endEntityInformation1.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
        // Convert from UserDataVOWS with standard DateFormat to endEntityInformation
        userDataVoWs.setStartTime(newTimeFormatRequest);
        userDataVoWs.setEndTime(newTimeFormatRequest);
        final EndEntityInformation endEntityInformation2 = ejbcaWSHelperSession.convertUserDataVOWS(userDataVoWs, 1, 2, 3, 4, 5);
        assertEquals("ExtendedInformation.CUSTOM_STARTTIME in new format was not correctly handled.", newTimeFormatStorage, endEntityInformation2.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
        assertEquals("ExtendedInformation.CUSTOM_ENDTIME in new format was not correctly handled.", newTimeFormatStorage, endEntityInformation2.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
        // Convert from UserDataVOWS with relative date format to endEntityInformation
        userDataVoWs.setStartTime(relativeTimeFormat);
        userDataVoWs.setEndTime(relativeTimeFormat);
        final EndEntityInformation endEntityInformation3 = ejbcaWSHelperSession.convertUserDataVOWS(userDataVoWs, 1, 2, 3, 4, 5);
        assertEquals("ExtendedInformation.CUSTOM_STARTTIME in relative format was not correctly handled.", relativeTimeFormat, endEntityInformation3.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
        assertEquals("ExtendedInformation.CUSTOM_ENDTIME in relative format was not correctly handled.", relativeTimeFormat, endEntityInformation3.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
        // Convert from endEntityInformation with standard DateFormat to UserDataVOWS
        final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs1 = ejbcaWSHelperSession.convertEndEntityInformation(endEntityInformation1, "CA1", "EEPROFILE", "CERTPROFILE", "HARDTOKENISSUER", "P12");
        // We expect that the server will respond using UTC
        assertEquals("CUSTOM_STARTTIME in new format was not correctly handled (VO to VOWS).", newTimeFormatResponse, userDataVoWs1.getStartTime());
        assertEquals("CUSTOM_ENDTIME in new format was not correctly handled (VO to VOWS).", newTimeFormatResponse, userDataVoWs1.getEndTime());
        // Convert from EndEntityInformation with relative date format to UserDataVOWS
        final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs3 = ejbcaWSHelperSession.convertEndEntityInformation(endEntityInformation3, "CA1", "EEPROFILE", "CERTPROFILE", "HARDTOKENISSUER", "P12");
        assertEquals("CUSTOM_STARTTIME in relative format was not correctly handled (VO to VOWS).", relativeTimeFormat, userDataVoWs3.getStartTime());
        assertEquals("CUSTOM_ENDTIME in relative format was not correctly handled (VO to VOWS).", relativeTimeFormat, userDataVoWs3.getEndTime());
        // Try some invalid start time date format
        userDataVoWs.setStartTime("12:32 2011-02-28");  // Invalid
        userDataVoWs.setEndTime("2011-02-28 12:32:00+00:00");   // Valid
        try {
            ejbcaWSHelperSession.convertUserDataVOWS(userDataVoWs, 1, 2, 3, 4, 5);
            fail("Conversion of illegal time format did not generate exception.");
        } catch (EjbcaException e) {
            assertEquals("Unexpected error code in exception.", ErrorCode.FIELD_VALUE_NOT_VALID, e.getErrorCode());
        }
        // Try some invalid end time date format
        userDataVoWs.setStartTime("2011-02-28 12:32:00+00:00"); // Valid
        userDataVoWs.setEndTime("12:32 2011-02-28");    // Invalid
        try {
            ejbcaWSHelperSession.convertUserDataVOWS(userDataVoWs, 1, 2, 3, 4, 5);
            fail("Conversion of illegal time format did not generate exception.");
        } catch (EjbcaException e) {
            assertEquals("Unexpected error code in exception.", ErrorCode.FIELD_VALUE_NOT_VALID, e.getErrorCode());
        }
        log.trace("<test36EjbcaWsHelperTimeFormatConversion()");
    }
    
    /** Simulate a simple SQL injection by sending the to-be-escaped char "'". */
    @Test
    public void test40EvilFind01() throws Exception {
        log.trace(">test40EvilFind01");
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("A' OR '1=1");
        try {
            List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertEquals("SQL injection caused results to be returned!", 0, userdatas.size());
        } catch (IllegalQueryException_Exception e) {
            fail("SQL injection did cause an unexpected error: " + e.getMessage());
        }
        log.trace("<test40EvilFind01");
    }

    @Test
    public void test40EvilFind02() throws Exception {
        log.trace(">test40EvilFind02");
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("A'' OR ''1=1");
        try {
            List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertEquals("SQL injection caused results to be returned!", 0, userdatas.size());
        } catch (IllegalQueryException_Exception e) {
            fail("SQL injection did cause an unexpected error: " + e.getMessage());
        }
        log.trace("<test40EvilFind02");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test41CertificateRequestWithSpecialChars01() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test" + rnd + ", O=foo\\+bar\\\"\\,, C=SE",
                "CN=test" + rnd + ",O=foo\\+bar\\\"\\,,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test42CertificateRequestWithSpecialChars02() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test42CertificateRequestWithSpecialChars02" + rnd + ",O=foo/bar\\;123, C=SE",
                "CN=test42CertificateRequestWithSpecialChars02" + rnd + ",O=foo/bar/123,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test43CertificateRequestWithSpecialChars03() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test43CertificateRequestWithSpecialChars03" + rnd + ", O=foo+bar\\+123, C=SE",
                "CN=test43CertificateRequestWithSpecialChars03" + rnd + ",O=foo\\+bar\\+123,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test44CertificateRequestWithSpecialChars04() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test" + rnd + ", O=foo\\=bar, C=SE",
                "CN=test" + rnd + ",O=foo\\=bar,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test45CertificateRequestWithSpecialChars05() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test45CertificateRequestWithSpecialChars05" + rnd + ", O=\"foo=bar, C=SE\"",
                "CN=test45CertificateRequestWithSpecialChars05" + rnd + ",O=foo\\=bar\\, C\\=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test46CertificateRequestWithSpecialChars06() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test46CertificateRequestWithSpecialChars06" + rnd + ", O=\"foo+b\\+ar, C=SE\"",
                "CN=test46CertificateRequestWithSpecialChars06" + rnd + ",O=foo\\+b\\+ar\\, C\\=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test47CertificateRequestWithSpecialChars07() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test47CertificateRequestWithSpecialChars07" + rnd + ", O=\\\"foo+b\\+ar\\, C=SE\\\"",
                "CN=test47CertificateRequestWithSpecialChars07" + rnd + ",O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"");
    }

    /**
     * Test that all but one default certificate forbidden characters are substituted
     * with '/'.
     * The one not tested is the null character ('\0'). It is not tested since
     * it is not a valid xml character so the WS protocol can not handle it.
     */
    @Test
    public void test48CertificateRequestWithForbiddenCharsDefault() throws Exception {
        long rnd = secureRandom.nextLong();
        cesecoreConfigurationProxySession.setConfigurationValue(forbiddenCharsKey, null);
        testCertificateRequestWithSpecialChars(
                "CN=test48CertificateRequestWithForbiddenCharsDefault" + rnd + ",O=|\n|\r|;|A|!|`|?|$|~|, C=SE",
                "CN=test48CertificateRequestWithForbiddenCharsDefault" + rnd +   ",O=|/|/|/|A|/|/|/|/|/|,C=SE");
    }

    /**
     * Same as {@link #test48CertificateRequestWithForbiddenCharsDefault()} but setting
     * default values in config.
     */
    @Test
    public void test49CertificateRequestWithForbiddenCharsDefinedAsDefault() throws Exception {
        long rnd = secureRandom.nextLong();
        cesecoreConfigurationProxySession.setConfigurationValue(forbiddenCharsKey, "\n\r;!\u0000%`?$~");
        testCertificateRequestWithSpecialChars(
                "CN=test49CertificateRequestWithForbiddenCharsDefinedAsDefault" + rnd + ",O=|\n|\r|;|A|!|`|?|$|~|, C=SE",
                "CN=test49CertificateRequestWithForbiddenCharsDefinedAsDefault" + rnd +   ",O=|/|/|/|A|/|/|/|/|/|,C=SE");
    }

    /**
     * Test to define some forbidden chars.
     */
    @Test
    public void test50CertificateRequestWithForbiddenCharsDefinedBogus() throws Exception {
        long rnd = secureRandom.nextLong();
        cesecoreConfigurationProxySession.setConfigurationValue(forbiddenCharsKey, "tset");
        try {
            testCertificateRequestWithSpecialChars(
                    "CN=test" + rnd +   ",O=|\n|\r|;|A|!|`|?|$|~|, C=SE",
                    "CN=////" + rnd + ",O=|\n|\r|\\;|A|!|`|?|$|~|,C=SE");
        } finally {
            // we must remove this bogus settings otherwise next setupAdmin() will fail
            cesecoreConfigurationProxySession.setConfigurationValue(forbiddenCharsKey, "");
        }
    }

    /**
     * Test that no forbidden chars work
     */
    @Test
    public void test51CertificateRequestWithNoForbiddenChars() throws Exception {
        long rnd = secureRandom.nextLong();
        cesecoreConfigurationProxySession.setConfigurationValue(forbiddenCharsKey, "");
        // Using JDK8 \r is transformed into \n for some reason, expected will work if: O=|\n|\r|\\;|A|!|`|?|$|~|,C=SE
        testCertificateRequestWithSpecialChars(
                "CN=test51CertificateRequestWithNoForbiddenChars" + rnd +   ",O=|\n|\r|;|A|!|`|?|$|~|, C=SE",
                "CN=test51CertificateRequestWithNoForbiddenChars" + rnd +   ",O=|\n|\r|\\;|A|!|`|?|$|~|,C=SE");
    }


    /**
     * Tests that the provided cardnumber is stored in the EndEntityInformation 
     * and that when querying for EndEntityInformation the cardnumber is 
     * returned.
     * @throws Exception in case of error
     */
    @Test
    public void test48CertificateRequestWithCardNumber() throws Exception {
        String userName = "wsRequestCardNumber" + new SecureRandom().nextLong();
        
        // Generate a CSR
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        PKCS10CertificationRequest pkcs10 = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", CertTools.stringToBcX500Name("CN=NOUSED"),
                keys.getPublic(), new DERSet(), keys.getPrivate(), null);
        final String csr = new String(Base64.encode(pkcs10.toASN1Structure().getEncoded()));
        
        // Set some user data
        final UserDataVOWS userData = new UserDataVOWS();
        userData.setUsername(userName);
        userData.setPassword(PASSWORD);
        userData.setClearPwd(true);
        userData.setSubjectDN("CN=test" + secureRandom.nextLong() + ", UID=" + userName + ", O=Test, C=SE");
        userData.setCaName(getAdminCAName());
        userData.setEmail(null);
        userData.setSubjectAltName(null);
        userData.setStatus(EndEntityConstants.STATUS_NEW);
        userData.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        userData.setEndEntityProfileName("EMPTY");
        userData.setCertificateProfileName("ENDUSER");

        // Set the card number
        userData.setCardNumber("1234fa");
        
        // Issue a certificate
        CertificateResponse response = ejbcaraws.certificateRequest(userData, csr, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
        assertNotNull("null response", response);
        
        // Check that the cardnumber was stored in the EndEntityInformation
        EndEntityInformation endEntity = endEntityAccessSession.findUser(intAdmin, userName);
        assertEquals("stored cardnumber ejb", "1234fa", endEntity.getCardNumber());
        
        // Check that the cardnumber is also available when querying using WS
        UserMatch criteria = new UserMatch();
        criteria.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        criteria.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        criteria.setMatchvalue(userName);
        UserDataVOWS user = ejbcaraws.findUser(criteria).get(0);
        assertEquals("stored cardnumber ws", "1234fa", user.getCardNumber());
    }
    
    @Test
    public void test52GetProfileFromID() throws Exception {
        getEndEntityProfileFromID();
        getCertificateProfileFromID();
    }

    @Test
    public void test53CertificateRequestWithoutDnOverrideFromEndEntityInformation() throws Exception {
        final long rnd = Math.abs(secureRandom.nextLong());
        testCertificateRequestWithEeiDnOverride(false, true,
                "L=locality,OU=OU1,JURISDICTIONLOCALITY=jlocality,CN=rox" + rnd + ".primekey.se,C=SE,ST=Sthlm,OU=OU2,O=PrimeKey,JURISDICTIONCOUNTRY=SE,SN=12345,BUSINESSCATEGORY=Private Organization",
                "JurisdictionCountry=SE,JurisdictionLocality=jlocality,BusinessCategory=Private Organization,CN=rox" + rnd + ".primekey.se,SN=12345,OU=OU2,OU=OU1,O=PrimeKey,L=locality,ST=Sthlm,C=SE");
    }

    @Test
    public void test54SoftTokenRequestWithoutDnOverrideFromEndEntityInformation() throws Exception {
        final long rnd = Math.abs(secureRandom.nextLong());
        testCertificateRequestWithEeiDnOverride(false, false,
                "L=locality,OU=OU1,JURISDICTIONLOCALITY=jlocality,CN=rox" + rnd + ".primekey.se,C=SE,ST=Sthlm,OU=OU2,O=PrimeKey,JURISDICTIONCOUNTRY=SE,SN=12345,BUSINESSCATEGORY=Private Organization",
                "JurisdictionCountry=SE,JurisdictionLocality=jlocality,BusinessCategory=Private Organization,CN=rox" + rnd + ".primekey.se,SN=12345,OU=OU2,OU=OU1,O=PrimeKey,L=locality,ST=Sthlm,C=SE");
    }

    @Test
    public void test55CertificateRequestWithDnOverrideFromEndEntityInformation() throws Exception {
        final long rnd = Math.abs(secureRandom.nextLong());
        testCertificateRequestWithEeiDnOverride(true, true,
                "L=locality,OU=OU1,JURISDICTIONLOCALITY=jlocality,CN=rox" + rnd + ".primekey.se,C=SE,ST=Sthlm,OU=OU2,O=PrimeKey,JURISDICTIONCOUNTRY=SE,SN=12345,BUSINESSCATEGORY=Private Organization",
                "L=locality,OU=OU1,JurisdictionLocality=jlocality,CN=rox" + rnd + ".primekey.se,C=SE,ST=Sthlm,OU=OU2,O=PrimeKey,JurisdictionCountry=SE,SN=12345,BusinessCategory=Private Organization");
    }

    @Test
    public void test56SoftTokenRequestWithDnOverrideFromEndEntityInformation() throws Exception {
        final long rnd = Math.abs(secureRandom.nextLong());
        testCertificateRequestWithEeiDnOverride(true, false,
                "L=locality,OU=OU1,JURISDICTIONLOCALITY=jlocality,CN=rox" + rnd + ".primekey.se,C=SE,ST=Sthlm,OU=OU2,O=PrimeKey,JURISDICTIONCOUNTRY=SE,SN=12345,BUSINESSCATEGORY=Private Organization",
                "L=locality,OU=OU1,JurisdictionLocality=jlocality,CN=rox" + rnd + ".primekey.se,C=SE,ST=Sthlm,OU=OU2,O=PrimeKey,JurisdictionCountry=SE,SN=12345,BusinessCategory=Private Organization");
    }

    @Test
    public void test57CertificateRequestWithDnOverrideFromEndEntityInformation() throws Exception {
        cesecoreConfigurationProxySession.setConfigurationValue(forbiddenCharsKey, "\n\r;!\u0000%`?$~");
        final long rnd = Math.abs(secureRandom.nextLong());
        testCertificateRequestWithEeiDnOverride(true, true,
                "L=locality,OU=OU1, JURISDICTIONLOCALITY= jlocality ,CN=,CN=rox" + rnd + ".primekey.se;C=SE,ST=Sthlm\n,OU=OU2 ,O=PrimeKey,JURISDICTIONCOUNTRY=SE+SN=12345,BUSINESSCATEGORY=Private Organization",
                "L=locality,OU=OU1,JurisdictionLocality=jlocality,CN=rox" + rnd + ".primekey.se/C\\=SE,ST=Sthlm/,OU=OU2,O=PrimeKey,JurisdictionCountry=SE\\+SN\\=12345,BusinessCategory=Private Organization");
    }

    @Test
    public void test58SoftTokenRequestWithDnOverrideFromEndEntityInformation() throws Exception {
        cesecoreConfigurationProxySession.setConfigurationValue(forbiddenCharsKey, "\n\r;!\u0000%`?$~");
        final long rnd = Math.abs(secureRandom.nextLong());
        testCertificateRequestWithEeiDnOverride(true, false,
                "L=locality,OU=OU1, JURISDICTIONLOCALITY= jlocality ,CN=,CN=rox" + rnd + ".primekey.se;C=SE,ST=Sthlm\n,OU=OU2 ,O=PrimeKey,JURISDICTIONCOUNTRY=SE+SN=12345,BUSINESSCATEGORY=Private Organization",
                "L=locality,OU=OU1,JurisdictionLocality=jlocality,CN=rox" + rnd + ".primekey.se/C\\=SE,ST=Sthlm/,OU=OU2,O=PrimeKey,JurisdictionCountry=SE\\+SN\\=12345,BusinessCategory=Private Organization");
    }

    /* This is apparently allowed but puts the system in a world of pain, since other functions are not adapted to handle an empty subjectDN
    @Test
    public void test59CertificateRequestWithoutDnOverrideFromEndEntityInformation() throws Exception {
        try {
            testCertificateRequestWithEeiDnOverride(false, true, "", "");
            fail("Was able to provide an empty subjectDN.");
        } catch (EjbcaException_Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @Test
    public void test60CertificateRequestWithDnOverrideFromEndEntityInformation() throws Exception {
        try {
            testCertificateRequestWithEeiDnOverride(true, true, "", "");
            fail("Was able to provide an empty subjectDN.");
        } catch (EjbcaException_Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @Test
    public void test61SoftTokenRequestWithoutDnOverrideFromEndEntityInformation() throws Exception {
        try {
            testCertificateRequestWithEeiDnOverride(false, false, "", "");
            fail("Was able to provide an empty subjectDN.");
        } catch (EjbcaException_Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @Test
    public void test62SoftTokenRequestWithDnOverrideFromEndEntityInformation() throws Exception {
        try {
            testCertificateRequestWithEeiDnOverride(true, false, "", "");
            fail("Was able to provide an empty subjectDN.");
        } catch (EjbcaException_Exception e) {
            log.error(e.getMessage(), e);
        }
    }
    */
    
    @Test
    public void test70CreateSoftCryptoToken() throws Exception {
        log.trace(">test70CreateSoftCryptoToken()");
        log.debug("Enterprise Edition: " + enterpriseEjbBridgeSession.isRunningEnterprise());
        assumeTrue("Enterprise Edition only. Skipping the test", enterpriseEjbBridgeSession.isRunningEnterprise());
        
        String ctname = "NewTestCryptoTokenThroughWS";
        
        // Remove any residues from earlier test runs
        Integer ctid = cryptoTokenManagementSession.getIdFromName(ctname);
        if(ctid != null) {
            cryptoTokenManagementSession.deleteCryptoToken(intAdmin, ctid.intValue());
        }
        
        try {
            ArrayList<KeyValuePair> cryptotokenProperties = new ArrayList<>();
            KeyValuePair allowExtract = new KeyValuePair();
            allowExtract.setKey(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY);
            allowExtract.setValue(Boolean.toString(false));
            cryptotokenProperties.add(allowExtract);
            KeyValuePair nodefaultPwd = new KeyValuePair();
            nodefaultPwd.setKey(SoftCryptoToken.NODEFAULTPWD);
            nodefaultPwd.setValue(Boolean.TRUE.toString());
            cryptotokenProperties.add(nodefaultPwd);
            
            ejbcaraws.createCryptoToken(ctname, "SoftCryptoToken", "1234", false, cryptotokenProperties);
            ctid = cryptoTokenManagementSession.getIdFromName(ctname);
            assertNotNull("Creating a new SoftCryptoToken failed", ctid);
            CryptoTokenInfo token = cryptoTokenManagementSession.getCryptoTokenInfo(intAdmin, ctid.intValue());
            
            Properties ctproperties = token.getCryptoTokenProperties();
            assertEquals(3, ctproperties.keySet().size());
            assertTrue(ctproperties.containsKey(SoftCryptoToken.NODEFAULTPWD));
            assertEquals(ctproperties.getProperty(SoftCryptoToken.NODEFAULTPWD), Boolean.TRUE.toString());
            
            assertEquals("SoftCryptoToken", token.getType());
            assertFalse(Boolean.getBoolean((String)token.getCryptoTokenProperties().get(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY)));
            assertTrue(token.isActive());
            cryptoTokenManagementSession.deactivate(intAdmin, ctid.intValue());
            assertFalse(cryptoTokenManagementSession.isCryptoTokenStatusActive(intAdmin, ctid.intValue()));
            cryptoTokenManagementSession.activate(intAdmin, ctid.intValue(), "1234".toCharArray());
            assertTrue(cryptoTokenManagementSession.isCryptoTokenStatusActive(intAdmin, ctid.intValue()));
        } finally {
            ctid = cryptoTokenManagementSession.getIdFromName(ctname);
            if(ctid != null) {
                cryptoTokenManagementSession.deleteCryptoToken(intAdmin, ctid.intValue());
            }
        }
        log.trace("<test70CreateSoftCryptoToken()");
    }

    @Test
    public void test71GenerateCryptoTokenKeys() throws Exception {
        log.trace(">test71GenerateCryptoTokenKeys()");
        log.debug("Enterprise Edition: " + enterpriseEjbBridgeSession.isRunningEnterprise());
        assumeTrue("Enterprise Edition only. Skipping the test", enterpriseEjbBridgeSession.isRunningEnterprise());

        String ctname = "NewTestCryptoTokenThroughWS";
        
        // Remove any residues from earlier test runs
        Integer ctid = cryptoTokenManagementSession.getIdFromName(ctname);
        if(ctid != null) {
            cryptoTokenManagementSession.deleteCryptoToken(intAdmin, ctid.intValue());
        }
        
        try {
            ArrayList<KeyValuePair> cryptotokenProperties = new ArrayList<>();            
            KeyValuePair allowExtract = new KeyValuePair();
            allowExtract.setKey(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY);
            allowExtract.setValue(Boolean.toString(false));
            cryptotokenProperties.add(allowExtract);
            KeyValuePair nodefaultPwd = new KeyValuePair();
            nodefaultPwd.setKey(SoftCryptoToken.NODEFAULTPWD);
            nodefaultPwd.setValue(Boolean.TRUE.toString());
            cryptotokenProperties.add(nodefaultPwd);
            
            ejbcaraws.createCryptoToken(ctname, "SoftCryptoToken", "1234", false, cryptotokenProperties);
            ctid = cryptoTokenManagementSession.getIdFromName(ctname);
            
            String keyAlias = "testWSGeneratedKeys";
            ejbcaraws.generateCryptoTokenKeys(ctname, keyAlias, "RSA1024");
            List<String> keyAliases = cryptoTokenManagementSession.getKeyPairAliases(intAdmin, ctid.intValue());
            assertTrue(keyAliases.contains(keyAlias));
            KeyPairInfo keyInfo = cryptoTokenManagementSession.getKeyPairInfo(intAdmin, ctid.intValue(), keyAlias);
            assertEquals("RSA", keyInfo.getKeyAlgorithm());
            assertEquals("1024", keyInfo.getKeySpecification());
        } finally {
            ctid = cryptoTokenManagementSession.getIdFromName(ctname);
            if(ctid != null) {
                cryptoTokenManagementSession.deleteCryptoToken(intAdmin, ctid.intValue());
            }
        }
        log.trace("<test71GenerateCryptoTokenKeys()");
    }

    @Test
    public void test72CreateCA() throws Exception {
        // ECA-4219 Test: WS call create CA with key validator.
        log.trace(">test72CreateCA()");
        log.debug("Enterprise Edition: " + enterpriseEjbBridgeSession.isRunningEnterprise());
        assumeTrue("Enterprise Edition only. Skipping the test", enterpriseEjbBridgeSession.isRunningEnterprise());
        final String caName = "NewTestCAThroughWS";
        final String cryptoTokenName = caName + "CryptoToken";
        // Remove any residues from earlier test runs
        if (caSession.existsCa(caName)) {
            caSession.removeCA(intAdmin, caSession.getCAInfo(intAdmin, caName).getCAId());
        }
        Integer cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
        if (cryptoTokenId != null) {
            cryptoTokenManagementSession.deleteCryptoToken(intAdmin, cryptoTokenId.intValue());
        }
        try {
            // Create CryptoToken
            final List<KeyValuePair> cryptoTokenProperties = new ArrayList<>();
            cryptoTokenProperties.add(getKeyValuePair(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.FALSE.toString()));
            cryptoTokenProperties.add(getKeyValuePair(SoftCryptoToken.NODEFAULTPWD, Boolean.TRUE.toString()));
            ejbcaraws.createCryptoToken(cryptoTokenName, "SoftCryptoToken", "1234", true, cryptoTokenProperties);
            cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
            // Generate CA key pairs
            final String decKeyAlias = CAToken.SOFTPRIVATEDECKEYALIAS;
            ejbcaraws.generateCryptoTokenKeys(cryptoTokenName, decKeyAlias, "RSA1024");
            final String signKeyAlias = CAToken.SOFTPRIVATESIGNKEYALIAS;
            ejbcaraws.generateCryptoTokenKeys(cryptoTokenName, signKeyAlias, "RSA1024");
            final String testKeyAlias = "test72CreateCATestKey";
            ejbcaraws.generateCryptoTokenKeys(cryptoTokenName, testKeyAlias, "secp256r1");
            // Construct the CAToken's properties
            final List<KeyValuePair> purposeKeyMapping = new ArrayList<>();
            purposeKeyMapping.add(getKeyValuePair(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, decKeyAlias));
            purposeKeyMapping.add(getKeyValuePair(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, signKeyAlias));
            purposeKeyMapping.add(getKeyValuePair(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, signKeyAlias));
            purposeKeyMapping.add(getKeyValuePair(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, testKeyAlias));            
            // Try to create a CA signed by an external CA. It should fail.
            try {
                ejbcaraws.createCA(caName, "CN="+caName, "x509", 3L, null, "SHA256WithRSA", CAInfo.SIGNEDBYEXTERNALCA, cryptoTokenName, purposeKeyMapping, null);
                fail("It was possible to create a CA signed by an external CA");
            } catch (EjbcaException_Exception e) {
                if (!e.getFaultInfo().getErrorCode().getInternalErrorCode().equals(ErrorCode.SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED.getInternalErrorCode())) {
                    throw e;
                }
            }
            // Try to create a CA that already exists. It should fail
            final String existingTestCA = "WSCreateCATestTestingExistingCA";
            CaTestCase.createTestCA(existingTestCA);
            try {
                ejbcaraws.createCA(existingTestCA, caSession.getCAInfo(intAdmin, existingTestCA).getSubjectDN(), "x509", 3L, null, "SHA256WithRSA", 
                        CAInfo.SELFSIGNED, cryptoTokenName, purposeKeyMapping, null);
                fail("It was possible to create a CA even though the CA already exists");
            } catch (EjbcaException_Exception e) {
                if (!e.getFaultInfo().getErrorCode().getInternalErrorCode().equals(ErrorCode.CA_ALREADY_EXISTS.getInternalErrorCode())) {
                    throw e;
                }
                caSession.removeCA(intAdmin, caSession.getCAInfo(intAdmin, existingTestCA).getCAId());
            }
            // Try to create a CA. It should succeed (Happy path test)
            ejbcaraws.createCA(caName, "CN="+caName, "x509", 3L, null, "SHA256WithRSA", CAInfo.SELFSIGNED, cryptoTokenName, purposeKeyMapping, null);
            // Verify the new CA's parameters
            final CAInfo caInfo = caSession.getCAInfo(intAdmin, caName);
            assertNotNull(caInfo);
            assertEquals(caName, caInfo.getName());
            assertEquals("CN=" + caName, caInfo.getSubjectDN());
            assertEquals(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, caInfo.getCertificateProfileId());
            assertEquals(CAInfo.SELFSIGNED, caInfo.getSignedBy());
            assertEquals(CAInfo.CATYPE_X509, caInfo.getCAType());
        } finally {
            if (caSession.existsCa(caName)) {
                caSession.removeCA(intAdmin, caSession.getCAInfo(intAdmin, caName).getCAId());
            }
            cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
            if (cryptoTokenId != null) {
                cryptoTokenManagementSession.deleteCryptoToken(intAdmin, cryptoTokenId.intValue());
            }
        }
        log.trace("<test72CreateCA()");
    }

    private KeyValuePair getKeyValuePair(final String key, final String value) {
        final KeyValuePair keyValuePair = new KeyValuePair();
        keyValuePair.setKey(key);
        keyValuePair.setValue(value);
        return keyValuePair;
    }

    @Test
    public void test73ManageSubjectInRole() throws Exception {
        log.trace(">test73AddSubjectToRole()");
        log.debug("Enterprise Edition: " + enterpriseEjbBridgeSession.isRunningEnterprise());
        assumeTrue("Enterprise Edition only. Skipping the test", enterpriseEjbBridgeSession.isRunningEnterprise());
        
        String rolename = "TestWSNewAccessRole";
        String testAdminUsername = "newWsAdminUserName";
        
        // Remove any residues from earlier test runs
        final Role oldRole = roleSession.getRole(intAdmin, null, rolename);
        if (oldRole!=null) {
            roleSession.deleteRoleIdempotent(intAdmin, oldRole.getRoleId());
        }
        File fileHandle = null;
        try {
            CAInfo cainfo = caSession.getCAInfo(intAdmin, getAdminCAName());
            assertNotNull("No CA with name " + getAdminCAName() + " was found.", cainfo);
            
            // Create/update the admin end entity and issue its certificate
            EndEntityInformation adminUser = endEntityAccessSession.findUser(intAdmin, testAdminUsername);
            if(adminUser == null) {
                adminUser = new EndEntityInformation();
                adminUser.setUsername(testAdminUsername);
                adminUser.setPassword("foo123");
                adminUser.setDN("CN="+testAdminUsername);
                adminUser.setCAId(cainfo.getCAId());
                adminUser.setEmail(null);
                adminUser.setSubjectAltName(null);
                adminUser.setStatus(EndEntityConstants.STATUS_NEW);
                adminUser.setTokenType(SecConst.TOKEN_SOFT_JKS);
                adminUser.setEndEntityProfileId(SecConst.EMPTY_ENDENTITYPROFILE);
                adminUser.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
                adminUser.setType(new EndEntityType(EndEntityTypes.ENDUSER, EndEntityTypes.ADMINISTRATOR));
                log.info("Adding new user: "+adminUser.getUsername());
                endEntityManagementSession.addUser(intAdmin, adminUser, true);
            } else {
                adminUser.setStatus(EndEntityConstants.STATUS_NEW);
                adminUser.setPassword("foo123");
                log.info("Changing user: "+adminUser.getUsername());
                endEntityManagementSession.changeUser(intAdmin, adminUser, true);
            }
            fileHandle = BatchCreateTool.createUser(intAdmin, new File(P12_FOLDER_NAME), adminUser.getUsername());
            adminUser = endEntityAccessSession.findUser(intAdmin, testAdminUsername);
        
            // Create a new role
            log.info("Creating new role: "+rolename);
            final Role role = roleSession.persistRole(intAdmin, new Role(null, rolename, Arrays.asList(StandardRules.ROLE_ROOT.resource()), null));
            List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(intAdmin, role.getRoleId());
            assertTrue("New role "+rolename+" should have been empty.", roleMembers.isEmpty());
            
            // Add adminUser to a non-existing role. It should fail
            try {
                ejbcaraws.addSubjectToRole("NoneExistingRole", getAdminCAName(), X500PrincipalAccessMatchValue.WITH_FULLDN.name(), 
                        AccessMatchType.TYPE_EQUALCASE.name(), adminUser.getCertificateDN());
                fail("Succeeded in adding subject to a non-existing role");
            } catch(EjbcaException_Exception e) {
                if(!e.getFaultInfo().getErrorCode().getInternalErrorCode().equals(ErrorCode.ROLE_DOES_NOT_EXIST.getInternalErrorCode())) {
                    throw e;
                }
            }
            
            // Add adminUser to the new role. It should succeed
            ejbcaraws.addSubjectToRole(rolename, getAdminCAName(), X500PrincipalAccessMatchValue.WITH_FULLDN.name(), 
                    AccessMatchType.TYPE_EQUALCASE.name(), adminUser.getCertificateDN());
            // Verify the admin data
            final Role roleAfterAdd = roleSession.getRole(intAdmin, null, rolename);
            final List<RoleMember> roleMembersAfterAdd = roleMemberSession.getRoleMembersByRoleId(intAdmin, roleAfterAdd.getRoleId());
            assertEquals("Failed to add subject to role.", 1, roleMembersAfterAdd.size());
            final RoleMember roleMember = roleMembersAfterAdd.get(0);
            assertEquals(cainfo.getCAId(), roleMember.getTokenIssuerId());
            assertEquals(X500PrincipalAccessMatchValue.WITH_FULLDN.getNumericValue(), roleMember.getTokenMatchKey());
            assertEquals(AccessMatchType.TYPE_EQUALCASE.getNumericValue(), roleMember.getTokenMatchOperator());
            assertEquals(adminUser.getCertificateDN(), roleMember.getTokenMatchValue());
            // Remove adminUser specified by a non-existing CA. It should fail
            try {
                ejbcaraws.removeSubjectFromRole(rolename, "NoneExistingCA", X500PrincipalAccessMatchValue.WITH_FULLDN.name(), 
                        AccessMatchType.TYPE_EQUALCASE.name(), adminUser.getCertificateDN());
                fail("Succeeded in adding subject to a non-existing role");
            } catch(EjbcaException_Exception e) {
                if(!e.getFaultInfo().getErrorCode().getInternalErrorCode().equals(ErrorCode.CA_NOT_EXISTS.getInternalErrorCode())) {
                    throw e;
                }
            }
            // Remove adminUser from the new role. It should succeed
            ejbcaraws.removeSubjectFromRole(rolename, getAdminCAName(), X500PrincipalAccessMatchValue.WITH_FULLDN.name(), 
                    AccessMatchType.TYPE_EQUALCASE.name(), adminUser.getCertificateDN());
            final Role roleAfterRemove = roleSession.getRole(intAdmin, null, rolename);
            final List<RoleMember> roleMembersAfterRemove = roleMemberSession.getRoleMembersByRoleId(intAdmin, roleAfterRemove.getRoleId());
            assertTrue("Failed to remove subject to role.", roleMembersAfterRemove.isEmpty());
        } finally {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, testAdminUsername, RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN);
            final Role role = roleSession.getRole(intAdmin, null, rolename);
            if (role!=null) {
                roleSession.deleteRoleIdempotent(intAdmin, role.getRoleId());
            }
            if( fileHandle != null) {
                FileTools.delete(fileHandle);
            }
        }
        log.trace("<test73AddSubjectToRole()");
    }

    @Test
    public void test74GetExpiredCerts() throws Exception {
        log.trace(">test74GetExpiredCert()");
        getExpiredCerts();
        log.trace("<test74GetExpiredCert()");
    }

    /**
     * Tests that the provided cardnumber is stored in the EndEntityInformation 
     * and that when querying for EndEntityInformation the cardnumber is 
     * returned.
     * @throws Exception in case of error
     */
    @Test
    public void test75CertificateRequestWithOnlyAltNames() throws Exception {
        final String username = "wsRequestOnlyAltNames" + new SecureRandom().nextLong();
        final String eepName = username;
        // Generate a CSR
        final KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final PKCS10CertificationRequest pkcs10 = CertTools.genPKCS10CertificationRequest(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, CertTools.stringToBcX500Name("CN=NOUSED"),
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);
        final String b64csr = new String(Base64.encode(pkcs10.toASN1Structure().getEncoded()));
        String fingerprint = null;
        try {
            // Setup an End Entity Profile that don't require any Subject DN and has a DNSName field
            final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
            endEntityProfile.setRequired(DnComponents.COMMONNAME, 0, false);
            endEntityProfileSession.addEndEntityProfile(intAdmin, eepName, endEntityProfile);
            // Set some user data
            final String SUBJECT_DN = "";
            final String SUBJECT_AN = "dNSName="+username+".primekey.se";
            final UserDataVOWS userDataVOWS = new UserDataVOWS();
            userDataVOWS.setUsername(username);
            userDataVOWS.setPassword(PASSWORD);
            userDataVOWS.setClearPwd(true);
            userDataVOWS.setSubjectDN(SUBJECT_DN);
            userDataVOWS.setCaName(getAdminCAName());
            userDataVOWS.setEmail(null);
            userDataVOWS.setSubjectAltName(SUBJECT_AN);
            userDataVOWS.setStatus(EndEntityConstants.STATUS_NEW);
            userDataVOWS.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
            userDataVOWS.setEndEntityProfileName(eepName);
            userDataVOWS.setCertificateProfileName("ENDUSER");
            // Issue a certificate
            final CertificateResponse certificateResponse = ejbcaraws.certificateRequest(userDataVOWS, b64csr, CertificateHelper.CERT_REQ_TYPE_PKCS10, null,
                    CertificateHelper.RESPONSETYPE_CERTIFICATE);
            assertNotNull("CertificateResponse was null.", certificateResponse);
            // Check that the Subject DN and AN was stored correctly in the certificate
            final X509Certificate x509Certificate = certificateResponse.getCertificate();
            fingerprint = CertTools.getFingerprintAsString(x509Certificate);
            log.debug(" Certificte SDN: " + CertTools.getSubjectDN(x509Certificate));
            log.debug(" Certificte SAN: " + CertTools.getSubjectAlternativeName(x509Certificate));
            assertEquals("Unexpected Subject DN stored in certificate.", SUBJECT_DN, CertTools.getSubjectDN(x509Certificate));
            assertEquals("Unexpected Subject AN stored in certificate.", SUBJECT_AN, CertTools.getSubjectAlternativeName(x509Certificate));
            // Check that the Subject DN and AN was stored correctly in the EE
            final EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(intAdmin, username);
            log.debug(" End entity SDN: " + endEntityInformation.getDN());
            log.debug(" End entity SAN: " + endEntityInformation.getSubjectAltName());
            assertEquals("Unexpected Subject DN stored in end entity.", SUBJECT_DN, endEntityInformation.getDN());
            assertEquals("Unexpected Subject AN stored in end entity.", SUBJECT_AN, endEntityInformation.getSubjectAltName());
        } finally {
            if (fingerprint!=null) {
                // Make sure to delete the certificate since the default AdminCA wont have "Enforce unique DN: false", so next round works
                internalCertificateStoreSession.removeCertificate(fingerprint);
            }
            try {
                endEntityManagementSession.deleteUser(intAdmin, username);
            } catch (AuthorizationDeniedException | NoSuchEndEntityException | RemoveException e) {
                log.debug("Error during cleanup: " + e.getMessage());
            }
            try {
                endEntityProfileSession.removeEndEntityProfile(intAdmin, eepName);
            } catch (AuthorizationDeniedException e) {
                log.debug("Error during cleanup: " + e.getMessage());
            }
        }
    }
    
    
    @Test
    public void test76ImportAndUpdateExternalCvcaCaCertificate() throws Exception {
        log.trace(">test76ImportAndUpdateExternalCvcaCaCertificate");
        log.debug("Enterprise Edition: " + enterpriseEjbBridgeSession.isRunningEnterprise());
        assumeTrue("Enterprise Edition only. Skipping the test", enterpriseEjbBridgeSession.isRunningEnterprise());
        
        try {
            // A: Imports a CA certificate of an external CVCA (CVC certificate with at least C=${ISO-3166-2}, CN != null).
            log.debug("Test import a CA certificate of an external CVCA.");
            String caname = "Test-Import-CVCA";
            removeCaIfExists(caname);
            final byte[] importFile = readDerFile("external_cvca_certificate_for_import.der");
            ejbcaraws.importCaCert(caname, importFile);
            assertTrue("Imported CVCA must exists.", caSession.existsCa(caname));
            CAInfo cainfo = caSession.getCAInfo(intAdmin, caname);
            assertEquals("CVCA must be a CVC CA.", cainfo.getCAType(), CAInfo.CATYPE_CVC);
            assertCertificateEquals("The imported CA certificate chain must match the CA certificate chain after import.", importFile, cainfo);
            
            // Exceptions: Import of the same CA again must throw a CAExistsException.
            log.debug("Test import a CA certificate of an external CVCA again (one time too much).");
            caname = "Test-Import-CVCA";
            try {
                ejbcaraws.importCaCert(caname, importFile);
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.INTERNAL_ERROR, "CA with name " + caname + " already exists.");
            }
            // Exceptions: Import of the same CA certificate again (with other name) must throw a CAExistsException.
            log.debug("Test import a CA certificate of an external CVCA again (with other name).");
            caname = "Test-Import-CVCA-new";
            removeCaIfExists(caname);
            try {
                ejbcaraws.importCaCert(caname, readPemFile("external_cvca_certificate_for_import.pem").getBytes());
                fail();
            } catch(Exception e) {
                final int caid = caSession.getCAInfo(intAdmin, "Test-Import-CVCA").getCAId();
                assertEjbcaException(e, ErrorCode.INTERNAL_ERROR, "CA with id " + caid + " already exists.");
            }
            
            // B: Updates a CA certificate of an external CVCA (CVC certificate with at least C=${ISO-3166-2}, CN != null).
            log.debug("Test update a CA certificate of an external CVCA.");
            caname = "Test-Import-CVCA";
            final byte[] updateFile = readDerFile("external_cvca_certificate_for_update.der");
            ejbcaraws.updateCaCert(caname, updateFile);
            cainfo = caSession.getCAInfo(intAdmin, caname);
            assertCertificateEquals("The updated CA certificate chain must replace the existing CA certificate chain.", updateFile, cainfo);
              
            // Exceptions: Update of the same CA again must throw a CertificateImportException.
            log.debug("Test update a CA certificate of an external CVCA again (one time to much).");
            caname = "Test-Import-CVCA";
            try {
                ejbcaraws.updateCaCert(caname, updateFile);
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.CERTIFICATE_IMPORT, "The CA certificate chain is already imported.");
            }
            
            // Exceptions: Import of technical invalid file must throw an EjbcaException with a CertificateParsingException.
            log.debug("Test import a CA certificate with an invalid PEM file.");
            try {
                ejbcaraws.importCaCert(caname, readPemFile("invalid_certificate.pem").getBytes());
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.INTERNAL_ERROR, null);
            }
            // Exceptions: Import of a certificate file with an invalid certificate chain must throw an EjbcaException with a CertificateImportException.
            log.debug("Test import a CA certificate with an invalid PEM certificate chain.");
            try {
                ejbcaraws.importCaCert(caname, readPemFile("invalid_certificate_chain.pem").getBytes());
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.CERTIFICATE_IMPORT, "The provided certificates does not form a full certificate chain.");
            }
        }
        finally { // Clean up.
            removeCaIfExists("Test-Import-CVCA");
        }
        log.trace("<test76ImportAndUpdateExternalCvcaCaCertificate");
    }
    
    @Test
    public void test77ImportAndUpdateExternalCscaCaCertificate() throws Exception {
        log.trace(">test77ImportAndUpdateExternalCscaCaCertificate");
        try {
            // A: Imports a CA certificate of an external CSCA (X.509 certificate with at least C=${ISO-3166-2}, CN != null and serialNumber != null).
            log.debug("Test import a CA certificate of an external CSCA.");
            String caname = "Test-Import-CSCA";
            removeCaIfExists(caname);
            
            final byte[] importFile = readPemFile("external_csca_certificate_for_import.pem").getBytes();
            ejbcaraws.importCaCert(caname, importFile);
            assertTrue("Imported CSCA must exists.", caSession.existsCa(caname));
            CAInfo cainfo = caSession.getCAInfo(intAdmin, caname);
            assertEquals("CSCA must be a X.509 CA.", cainfo.getCAType(), CAInfo.CATYPE_X509);
            assertCertificateEquals("The imported CA certificate chain must match the existing CA certificate chain after import.", importFile, cainfo);
            
            // Exceptions: Import of the same CA again must throw a CAExistsException.
            log.debug("Test import a CA certificate of an external CSCA again (one time too much).");
            caname = "Test-Import-CSCA";
            try {
                ejbcaraws.importCaCert(caname, readDerFile("external_csca_certificate_for_import.der"));
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.INTERNAL_ERROR, "CA with name " + caname + " already exists.");
            }
            // Exceptions: Import of the same CA certificate again (with other name) must throw a CAExistsException.
            log.debug("Test import a CA certificate of an external CSCA again (with other name).");
            caname = "Test-Import-CSCA-new";
            removeCaIfExists(caname);
            try {
                ejbcaraws.importCaCert(caname, readPemFile("external_csca_certificate_for_import.pem").getBytes());
                fail();
            } catch(Exception e) {
                final int caid = caSession.getCAInfo(intAdmin, "Test-Import-CSCA").getCAId();
                assertEjbcaException(e, ErrorCode.INTERNAL_ERROR, "CA with id " + caid + " already exists.");
            }
            if(caSession.existsCa(caname)) {
                log.debug("Remove CA " + caname + " before test.");
                caSession.removeCA(intAdmin, caSession.getCAInfo(intAdmin, caname).getCAId());
            }
            
            // B: Updates a CA certificate of an external CSCA (X.509 certificate with at least C=${ISO-3166-2}, CN != null and serialNumber != null).
            log.debug("Test update a CA certificate of an external CSCA.");
            caname = "Test-Import-CSCA";
            final byte[] updateFile = readDerFile("external_csca_certificate_for_update.der");
            ejbcaraws.updateCaCert(caname, updateFile);
            // Optional change of serialNumber could be checked here, but is stored in the CVCs key sequence ... 
            cainfo = caSession.getCAInfo(intAdmin, caname);
            assertCertificateEquals("The updated CA certificate chain must replace the existing CA certificate chain.", updateFile, cainfo);

            // Exceptions: Update of the same CA again must throw a CertificateImportException.
            log.debug("Test update a CA certificate of an external CSCA again (one time to much).");
            caname = "Test-Import-CSCA";
            try {
                ejbcaraws.updateCaCert(caname, readDerFile("external_csca_certificate_for_update.der"));
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.CERTIFICATE_IMPORT, "The CA certificate chain is already imported.");
            }
            // Exceptions: Update of a CA with a DN which does not match (except CSCA certificates with at least C=${ISO-3166-2}, CN != null and different serialNumber).
            log.debug("Test update a CA certificate of an external CA with different Subject-DN.");
            caname = "Test-Import-CSCA";
            try {
                ejbcaraws.updateCaCert(caname, readDerFile("external_cvca_certificate_for_update.der"));
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.CERTIFICATE_IMPORT, "Only able to update imported CA certificate if Subject DN of the leaf CA certificate is the same.");
            }
            
            // Exceptions: Import of technical invalid file must throw an EjbcaException with a CertificateParsingException.
            log.debug("Test import a CA certificate with an invalid PEM file.");
            try {
                ejbcaraws.importCaCert(caname, readPemFile("invalid_certificate.pem").getBytes());
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.INTERNAL_ERROR, null);
            }
            // Exceptions: Import of a certificate file with an invalid certificate chain must throw an EjbcaException with a CertificateImportException.
            log.debug("Test import a CA certificate with an invalid PEM certificate chain.");
            try {
                ejbcaraws.importCaCert(caname, readPemFile("invalid_certificate_chain.pem").getBytes());
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.CERTIFICATE_IMPORT, "The provided certificates does not form a full certificate chain.");
            }
        }
        finally { // Clean up.
            removeCaIfExists("Test-Import-CSCA");
        }
        log.trace("<test77ImportAndUpdateExternalCscaCaCertificate");
    }
    
    private void assertCertificateEquals(final String label, final byte[] left, final CAInfo caInfo) 
            throws CertificateParsingException, CertificateEncodingException {
        final List<CertificateWrapper> leftSide = CertTools.bytesToListOfCertificateWrapperOrThrow(left);
        final List<CertificateWrapper> rightSide = CertTools.bytesToListOfCertificateWrapperOrThrow(
                caInfo.getCertificateChain().iterator().next().getEncoded());
        assertEquals(label, leftSide.get(0).getCertificate(), rightSide.get(0).getCertificate());
        
    }
    
    private void removeCaIfExists(final String caname ) throws Exception {
        if(caSession.existsCa(caname)) {
            log.debug("Remove CA " + caname + " after test.");
            caSession.removeCA(intAdmin, caSession.getCAInfo(intAdmin, caname).getCAId());
        }
    }
    
    private void assertEjbcaException(final Exception exception, final ErrorCode errorCode, final String errorMessage) {
        assertTrue("EjbcaException expected.", exception instanceof EjbcaException_Exception);
        if (StringUtils.isNotEmpty(errorCode.getInternalErrorCode())) {
            assertEquals("Error code:",  errorCode.getInternalErrorCode(), ((EjbcaException_Exception) exception).getFaultInfo().getErrorCode().getInternalErrorCode());
        }
        if (StringUtils.isNotEmpty(errorMessage)) {
            assertEquals("Error message:", errorMessage, ((EjbcaException_Exception) exception).getMessage());
        }
    }
    
    private void testCertificateRequestWithEeiDnOverride(boolean allowDNOverrideByEndEntityInformation, boolean useCsr, String requestedSubjectDN, String expectedSubjectDN) throws Exception {
        if (certificateProfileSession.getCertificateProfileId(WS_TEST_CERTIFICATE_PROFILE_NAME) != 0) {
            certificateProfileSession.removeCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME);
        }
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setAllowDNOverrideByEndEntityInformation(allowDNOverrideByEndEntityInformation);
        certificateProfileSession.addCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME, profile);
        //This test will fail if EEP limitations are enabled
        GlobalConfiguration originalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        globalConfiguration.setEnableEndEntityProfileLimitations(false);
        globalConfigurationSession.saveConfiguration(intAdmin, globalConfiguration);
        try {
            String userName = "eeiDnOverride" + secureRandom.nextLong();
            final UserDataVOWS userData = new UserDataVOWS();
            userData.setUsername(userName);
            userData.setPassword(PASSWORD);
            userData.setClearPwd(true);
            userData.setSubjectDN(requestedSubjectDN);
            userData.setCaName(getAdminCAName());
            userData.setEmail(null);
            userData.setSubjectAltName(null);
            userData.setStatus(EndEntityConstants.STATUS_NEW);
            userData.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
            userData.setEndEntityProfileName("EMPTY");
            userData.setCertificateProfileName(WS_TEST_CERTIFICATE_PROFILE_NAME);
            final X509Certificate cert;
            if (useCsr) {
                KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
                PKCS10CertificationRequest pkcs10 = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", CertTools.stringToBcX500Name("CN=NOUSED"),
                        keys.getPublic(), new DERSet(), keys.getPrivate(), null);
                final String csr = new String(Base64.encode(pkcs10.toASN1Structure().getEncoded()));
                CertificateResponse response = ejbcaraws.certificateRequest(userData, csr, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
                cert = response.getCertificate();
            } else {
                KeyStore ksenv = ejbcaraws.softTokenRequest(userData, null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
                java.security.KeyStore keyStore = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", PASSWORD);
                assertNotNull(keyStore);
                Enumeration<String> en = keyStore.aliases();
                String alias = en.nextElement();
                if(!keyStore.isKeyEntry(alias)) {
                    alias = en.nextElement();
                }
                cert = (X509Certificate) keyStore.getCertificate(alias);
            }
            final List<Certificate> certificates = Arrays.asList(new Certificate[] {cert});
            log.info(certificates.size() + " certs.\n" + new String(CertTools.getPemFromCertificateChain(certificates)));
            X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
            String resultingSubjectDN = CeSecoreNameStyle.INSTANCE.toString(x500name);
            log.debug("x500name:           " + resultingSubjectDN);
            assertEquals("Unexpected transformation.", expectedSubjectDN, resultingSubjectDN);
            try {
                endEntityManagementSession.deleteUser(intAdmin, userName);
            } catch (NoSuchEndEntityException e) {
                // Ignore
            }
        } finally {
            if (certificateProfileSession.getCertificateProfileId(WS_TEST_CERTIFICATE_PROFILE_NAME) != 0) {
                certificateProfileSession.removeCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME);
            }
            globalConfigurationSession.saveConfiguration(intAdmin, originalConfiguration);
        }
    }

    private void testCertificateRequestWithSpecialChars(String requestedSubjectDN, String expectedSubjectDN) throws Exception {
        String userName = "wsSpecialChars" + secureRandom.nextLong();
        final UserDataVOWS userData = new UserDataVOWS();
        userData.setUsername(userName);
        userData.setPassword(PASSWORD);
        userData.setClearPwd(true);
        userData.setSubjectDN(requestedSubjectDN);
        userData.setCaName(getAdminCAName());
        userData.setEmail(null);
        userData.setSubjectAltName(null);
        userData.setStatus(EndEntityConstants.STATUS_NEW);
        userData.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        userData.setEndEntityProfileName("EMPTY");
        userData.setCertificateProfileName("ENDUSER");

        KeyStore ksenv = ejbcaraws.softTokenRequest(userData, null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        java.security.KeyStore keyStore = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", PASSWORD);
        assertNotNull(keyStore);
        Enumeration<String> en = keyStore.aliases();
        String alias = en.nextElement();
        if(!keyStore.isKeyEntry(alias)) {
            alias = en.nextElement();
        }
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        
        String resultingSubjectDN = cert.getSubjectDN().toString();
        assertEquals(requestedSubjectDN + " was transformed into " + resultingSubjectDN + " (not the expected " + expectedSubjectDN + ")", expectedSubjectDN,
                resultingSubjectDN);
        try {
            endEntityManagementSession.deleteUser(intAdmin, userName);
        } catch (NoSuchEndEntityException e) {
            // Ignore
        }
    }

    /**
     * Creates a "hardtoken" with certficates.
     */
    private void createHardToken(String username, String caName, String serialNumber) throws Exception {
        GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        boolean originalProfileSetting = gc.getEnableEndEntityProfileLimitations();
        gc.setEnableEndEntityProfileLimitations(false);
        globalConfigurationSession.saveConfiguration(intAdmin, gc);
        try {
            if (certificateProfileSession.getCertificateProfileId(WS_TEST_CERTIFICATE_PROFILE_NAME) != 0) {
                certificateProfileSession.removeCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME);
            }
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            profile.setAllowValidityOverride(true);
            certificateProfileSession.addCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME, profile);
            UserDataVOWS tokenUser1 = new UserDataVOWS();
            tokenUser1.setUsername(username);
            tokenUser1.setPassword(PASSWORD);
            tokenUser1.setClearPwd(true);
            tokenUser1.setSubjectDN("CN=" + username);
            tokenUser1.setCaName(caName);
            tokenUser1.setEmail(null);
            tokenUser1.setSubjectAltName(null);
            tokenUser1.setStatus(EndEntityConstants.STATUS_NEW);
            tokenUser1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
            tokenUser1.setEndEntityProfileName("EMPTY");
            tokenUser1.setCertificateProfileName("ENDUSER");
            KeyPair basickeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
            PKCS10CertificationRequest basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", CertTools.stringToBcX500Name("CN=NOTUSED"), basickeys
                    .getPublic(), new DERSet(), basickeys.getPrivate(), null);
            ArrayList<TokenCertificateRequestWS> requests = new ArrayList<>();
            TokenCertificateRequestWS tokenCertReqWS = new TokenCertificateRequestWS();
            tokenCertReqWS.setCAName(caName);
            tokenCertReqWS.setCertificateProfileName(WS_TEST_CERTIFICATE_PROFILE_NAME);
            tokenCertReqWS.setValidityIdDays("1");
            tokenCertReqWS.setPkcs10Data(basicpkcs10.getEncoded());
            tokenCertReqWS.setType(HardTokenConstants.REQUESTTYPE_PKCS10_REQUEST);
            requests.add(tokenCertReqWS);
            tokenCertReqWS = new TokenCertificateRequestWS();
            tokenCertReqWS.setCAName(caName);
            tokenCertReqWS.setCertificateProfileName("ENDUSER");
            tokenCertReqWS.setKeyalg("RSA");
            tokenCertReqWS.setKeyspec("1024");
            tokenCertReqWS.setType(HardTokenConstants.REQUESTTYPE_KEYSTORE_REQUEST);
            requests.add(tokenCertReqWS);
            HardTokenDataWS hardTokenDataWS = new HardTokenDataWS();
            hardTokenDataWS.setLabel(HardTokenConstants.LABEL_PROJECTCARD);
            hardTokenDataWS.setTokenType(HardTokenConstants.TOKENTYPE_SWEDISHEID);
            hardTokenDataWS.setHardTokenSN(serialNumber);
            PinDataWS basicPinDataWS = new PinDataWS();
            basicPinDataWS.setType(HardTokenConstants.PINTYPE_BASIC);
            basicPinDataWS.setInitialPIN("1234");
            basicPinDataWS.setPUK("12345678");
            PinDataWS signaturePinDataWS = new PinDataWS();
            signaturePinDataWS.setType(HardTokenConstants.PINTYPE_SIGNATURE);
            signaturePinDataWS.setInitialPIN("5678");
            signaturePinDataWS.setPUK("23456789");
            hardTokenDataWS.getPinDatas().add(basicPinDataWS);
            hardTokenDataWS.getPinDatas().add(signaturePinDataWS);
            List<TokenCertificateResponseWS> responses = ejbcaraws.genTokenCertificates(tokenUser1, requests, hardTokenDataWS, true, false);
            assertTrue(responses.size() == 2);
        } finally {
            certificateProfileSession.removeCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME);
            gc.setEnableEndEntityProfileLimitations(originalProfileSetting);
            globalConfigurationSession.saveConfiguration(intAdmin, gc);
        }
    } // createHardToken

    /**
     * Create a user a generate certificate.
     */
    private X509Certificate createUserAndCert(String username, int caID) throws Exception {
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, caID, null, null, new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword(PASSWORD);
        endEntityManagementSession.addUser(intAdmin, userdata, true);
        fileHandles.addAll(BatchCreateTool.createAllNew(intAdmin, new File(P12_FOLDER_NAME)));
        Collection<Certificate> userCerts = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username));
        assertTrue(userCerts.size() == 1);
        return (X509Certificate) userCerts.iterator().next();
    }
    
    /** Reads a PEM file by the class path. */
    private String readPemFile(final String filename) throws IOException {
        final InputStream stream = getClass().getResourceAsStream(filename);
        final StringWriter writer = new StringWriter();
        IOUtils.copy(stream, writer);
        IOUtils.closeQuietly(stream);
        return writer.toString();
    }

    /** Reads a DER file by the class path. */
    private byte[] readDerFile(final String filename) throws IOException {
        final InputStream stream = getClass().getResourceAsStream(filename);
        final byte[] data = new byte[stream.available()]; 
        stream.read(data);
        IOUtils.closeQuietly(stream);
        return data;
    }
}
