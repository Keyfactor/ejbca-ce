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

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.CaTestUtils;
import org.cesecore.ErrorCode;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.roles.RoleData;
import org.cesecore.util.Base64;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalTest;
import org.ejbca.core.model.hardtoken.HardTokenConstants;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.ws.client.gen.AlreadyRevokedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.HardTokenDataWS;
import org.ejbca.core.protocol.ws.client.gen.IllegalQueryException_Exception;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.PinDataWS;
import org.ejbca.core.protocol.ws.client.gen.RevokeStatus;
import org.ejbca.core.protocol.ws.client.gen.TokenCertificateRequestWS;
import org.ejbca.core.protocol.ws.client.gen.TokenCertificateResponseWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
import org.junit.After;
import org.junit.AfterClass;
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
    
    private final ApprovalExecutionSessionRemote approvalExecutionSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalExecutionSessionRemote.class);
    private final ApprovalSessionRemote approvalSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
    private final CAAdminSessionRemote caAdminSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final HardTokenSessionRemote hardTokenSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(HardTokenSessionRemote.class);
    private final GlobalConfigurationSessionRemote raAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    private static final CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private static String originalForbiddenChars;
    private final static SecureRandom secureRandom;
    private final static String forbiddenCharsKey = "forbidden.characters";
    static {
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e);
        }
    }

    @BeforeClass
    public static void beforeClass() throws Exception {
        adminBeforeClass();
        setupAccessRights(WS_ADMIN_ROLENAME);
        originalForbiddenChars = cesecoreConfigurationProxySession.getConfigurationValue(forbiddenCharsKey);
    }

    @Before
    public void setUpAdmin() throws Exception {
        adminSetUpAdmin();
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        cleanUpAdmins(WS_ADMIN_ROLENAME);
        cleanUpAdmins(WS_TEST_ROLENAME);
        cesecoreConfigurationProxySession.setConfigurationValue(forbiddenCharsKey, originalForbiddenChars);
        CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
        certificateProfileSession.removeCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME);
    }

    @Override
    public String getRoleName() {
        return WS_TEST_ROLENAME;
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
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
        assertEquals("Admin web page should return csp default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self'; frame-src 'self'; form-action 'self'; plugin-types application/pdf; reflected-xss block", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self'; frame-src 'self'; form-action 'self'; reflected-xss block", csp);
        assertEquals("Admin web page should return xcsp default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self'; frame-src 'self'; form-action 'self'; plugin-types application/pdf; reflected-xss block", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self'; frame-src 'self'; form-action 'self'; reflected-xss block", xcsp);
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
    public void test03_1GeneratePkcs10() throws Exception {
        generatePkcs10();
    }

    @Test
    public void test03_2GenerateCrmf() throws Exception {
        generateCrmf();
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
    public void test04GeneratePkcs12() throws Exception {
        generatePkcs12();
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

        // Generate random username and CA name
        String randomPostfix = Integer.toString(secureRandom.nextInt(999999));
        String caname = "wsRevocationCA" + randomPostfix;
        String username = "wsRevocationUser" + randomPostfix;
        int cryptoTokenId = 0;
        int caID = -1;
        try {
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(intAdmin, caname, "1024");
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            caID = RevocationApprovalTest.createApprovalCA(intAdmin, caname, CAInfo.REQ_APPROVAL_REVOCATION, caAdminSessionRemote, caSession, catoken);
            X509Certificate adminCert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(APPROVINGADMINNAME).iterator().next();
            Set<X509Certificate> credentials = new HashSet<X509Certificate>();
            credentials.add(adminCert);
            Set<Principal> principals = new HashSet<Principal>();
            principals.add(adminCert.getSubjectX500Principal());
            AuthenticationToken approvingAdmin = simpleAuthenticationProvider.authenticate(new AuthenticationSubject(principals, credentials));
            //AuthenticationToken approvingAdmin = new X509CertificateAuthenticationToken(principals, credentials);
            //Admin approvingAdmin = new Admin(adminCert, APPROVINGADMINNAME, null);
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
                        ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, certificateStoreSession, approvalSession, approvalExecutionSession, caID);
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
                        certificateStoreSession, approvalSession, approvalExecutionSession, caID);
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
                        ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY, certificateStoreSession, approvalSession, approvalExecutionSession, caID);
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
                        ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, certificateStoreSession, approvalSession, approvalExecutionSession, caID);
            } finally {
                hardTokenSessionRemote.removeHardToken(intAdmin, TOKENSERIALNUMBER);
            }
        } finally {
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
        keyRecover();
    }

    @Test
    public void test20bKeyRecoverAny() throws Exception {
        keyRecoverAny();
    }
    
    @Test
    public void test21GetAvailableCAs() throws Exception {
        getAvailableCAs();
    }

    @Test
    public void test22GetAuthorizedEndEntityProfiles() throws Exception {
        getAuthorizedEndEntityProfiles();
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
    public void test36EjbcaWsHelperTimeFormatConversion() throws CADoesntExistsException, ClassCastException, EjbcaException, AuthorizationDeniedException {
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
        final EndEntityInformation endEntityInformation1 = EjbcaWSHelper.convertUserDataVOWS(userDataVoWs, 1, 2, 3, 4, 5);
        assertEquals("CUSTOM_STARTTIME in old format was not correctly handled (VOWS to VO).", newTimeFormatStorage, endEntityInformation1.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
        assertEquals("CUSTOM_ENDTIME in old format was not correctly handled (VOWS to VO).", newTimeFormatStorage, endEntityInformation1.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
        // Convert from UserDataVOWS with standard DateFormat to endEntityInformation
        userDataVoWs.setStartTime(newTimeFormatRequest);
        userDataVoWs.setEndTime(newTimeFormatRequest);
        final EndEntityInformation endEntityInformation2 = EjbcaWSHelper.convertUserDataVOWS(userDataVoWs, 1, 2, 3, 4, 5);
        assertEquals("ExtendedInformation.CUSTOM_STARTTIME in new format was not correctly handled.", newTimeFormatStorage, endEntityInformation2.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
        assertEquals("ExtendedInformation.CUSTOM_ENDTIME in new format was not correctly handled.", newTimeFormatStorage, endEntityInformation2.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
        // Convert from UserDataVOWS with relative date format to endEntityInformation
        userDataVoWs.setStartTime(relativeTimeFormat);
        userDataVoWs.setEndTime(relativeTimeFormat);
        final EndEntityInformation endEntityInformation3 = EjbcaWSHelper.convertUserDataVOWS(userDataVoWs, 1, 2, 3, 4, 5);
        assertEquals("ExtendedInformation.CUSTOM_STARTTIME in relative format was not correctly handled.", relativeTimeFormat, endEntityInformation3.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
        assertEquals("ExtendedInformation.CUSTOM_ENDTIME in relative format was not correctly handled.", relativeTimeFormat, endEntityInformation3.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
        // Convert from endEntityInformation with standard DateFormat to UserDataVOWS
        final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs1 = EjbcaWSHelper.convertEndEntityInformation(endEntityInformation1, "CA1", "EEPROFILE", "CERTPROFILE", "HARDTOKENISSUER", "P12");
        // We expect that the server will respond using UTC
        assertEquals("CUSTOM_STARTTIME in new format was not correctly handled (VO to VOWS).", newTimeFormatResponse, userDataVoWs1.getStartTime());
        assertEquals("CUSTOM_ENDTIME in new format was not correctly handled (VO to VOWS).", newTimeFormatResponse, userDataVoWs1.getEndTime());
        // Convert from EndEntityInformation with relative date format to UserDataVOWS
        final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs3 = EjbcaWSHelper.convertEndEntityInformation(endEntityInformation3, "CA1", "EEPROFILE", "CERTPROFILE", "HARDTOKENISSUER", "P12");
        assertEquals("CUSTOM_STARTTIME in relative format was not correctly handled (VO to VOWS).", relativeTimeFormat, userDataVoWs3.getStartTime());
        assertEquals("CUSTOM_ENDTIME in relative format was not correctly handled (VO to VOWS).", relativeTimeFormat, userDataVoWs3.getEndTime());
        // Try some invalid start time date format
        userDataVoWs.setStartTime("12:32 2011-02-28");  // Invalid
        userDataVoWs.setEndTime("2011-02-28 12:32:00+00:00");   // Valid
        try {
            EjbcaWSHelper.convertUserDataVOWS(userDataVoWs, 1, 2, 3, 4, 5);
            fail("Conversion of illegal time format did not generate exception.");
        } catch (EjbcaException e) {
            assertEquals("Unexpected error code in exception.", ErrorCode.FIELD_VALUE_NOT_VALID, e.getErrorCode());
        }
        // Try some invalid end time date format
        userDataVoWs.setStartTime("2011-02-28 12:32:00+00:00"); // Valid
        userDataVoWs.setEndTime("12:32 2011-02-28");    // Invalid
        try {
            EjbcaWSHelper.convertUserDataVOWS(userDataVoWs, 1, 2, 3, 4, 5);
            fail("Conversion of illegal time format did not generate exception.");
        } catch (EjbcaException e) {
            assertEquals("Unexpected error code in exception.", ErrorCode.FIELD_VALUE_NOT_VALID, e.getErrorCode());
        }
        log.trace("<test36EjbcaWsHelperTimeFormatConversion()");
    }
    
    /**
     * Simulate a simple SQL injection by sending the illegal char "'".
     * 
     * @throws Exception
     */
    @Test
    public void test40EvilFind01() throws Exception {
        log.trace(">testEvilFind01()");
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("A' OR '1=1");
        try {
            List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            fail("SQL injection did not cause an error! " + userdatas.size());
        } catch (IllegalQueryException_Exception e) {
            // NOPMD, this should be thrown and we ignore it because we fail if
            // it is not thrown
        }
        log.trace("<testEvilFind01()");
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
                "CN=test" + rnd + ",O=foo/bar\\;123, C=SE",
                "CN=test" + rnd + ",O=foo/bar/123,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test43CertificateRequestWithSpecialChars03() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test" + rnd + ", O=foo+bar\\+123, C=SE",
                "CN=test" + rnd + ",O=foo\\+bar\\+123,C=SE");
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
                "CN=test" + rnd + ", O=\"foo=bar, C=SE\"",
                "CN=test" + rnd + ",O=foo\\=bar\\, C\\=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test46CertificateRequestWithSpecialChars06() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test" + rnd + ", O=\"foo+b\\+ar, C=SE\"",
                "CN=test" + rnd + ",O=foo\\+b\\+ar\\, C\\=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test47CertificateRequestWithSpecialChars07() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test" + rnd + ", O=\\\"foo+b\\+ar\\, C=SE\\\"",
                "CN=test" + rnd + ",O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"");
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
                "CN=test" + rnd + ",O=|\n|\r|;|A|!|`|?|$|~|, C=SE",
                "CN=test" + rnd +   ",O=|/|/|/|A|/|/|/|/|/|,C=SE");
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
                "CN=test" + rnd + ",O=|\n|\r|;|A|!|`|?|$|~|, C=SE",
                "CN=test" + rnd +   ",O=|/|/|/|A|/|/|/|/|/|,C=SE");
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
        testCertificateRequestWithSpecialChars(
                "CN=test" + rnd +   ",O=|\n|\r|;|A|!|`|?|$|~|, C=SE",
                "CN=test" + rnd + ",O=|\n|\r|\\;|A|!|`|?|$|~|,C=SE");
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
        userData.setStatus(UserDataVOWS.STATUS_NEW);
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
        String ctname = "NewTestCryptoTokenThroughWS";
        Integer ctid = cryptoTokenManagementSession.getIdFromName(ctname);
        if(ctid != null) {
            cryptoTokenManagementSession.deleteCryptoToken(intAdmin, ctid.intValue());
        }
        
        try {
            
            Properties cryptotokenProperties = new Properties();
            cryptotokenProperties.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.toString(false));
            cryptotokenProperties.setProperty(SoftCryptoToken.NODEFAULTPWD, Boolean.TRUE.toString());
            
            ejbcaraws.createCryptoToken(ctname, "SoftCryptoToken", "1234", false, cryptotokenProperties);
            ctid = cryptoTokenManagementSession.getIdFromName(ctname);
            assertNotNull("Creating a new SoftCryptoToken failed", ctid);
            CryptoTokenInfo token = cryptoTokenManagementSession.getCryptoTokenInfo(intAdmin, ctid.intValue());
            
            cryptotokenProperties = token.getCryptoTokenProperties();
            assertEquals(cryptotokenProperties.keySet().size(), 3);
            assertTrue(cryptotokenProperties.containsKey(SoftCryptoToken.NODEFAULTPWD));
            assertEquals(cryptotokenProperties.getProperty(SoftCryptoToken.NODEFAULTPWD), Boolean.TRUE.toString());
            
            assertEquals("SoftCryptoToken", token.getType());
            assertFalse(Boolean.getBoolean((String)token.getCryptoTokenProperties().get(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY)));
            assertTrue(token.isActive());
            cryptoTokenManagementSession.deactivate(intAdmin, ctid.intValue());
            assertFalse(cryptoTokenManagementSession.isCryptoTokenStatusActive(intAdmin, ctid.intValue()));
            cryptoTokenManagementSession.activate(intAdmin, ctid.intValue(), "1234".toCharArray());
            assertTrue(cryptoTokenManagementSession.isCryptoTokenStatusActive(intAdmin, ctid.intValue()));
        } catch (RuntimeException e) {
            if(StringUtils.equals("This method can only be used in Enterprise edition.", e.getMessage())) {
                log.info("This feature is an enterprise-only feature and cannot be accessed here. Skipping this test");
            } else {
                throw e;
            }
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
        String ctname = "NewTestCryptoTokenThroughWS";
        Integer ctid = cryptoTokenManagementSession.getIdFromName(ctname);
        if(ctid != null) {
            cryptoTokenManagementSession.deleteCryptoToken(intAdmin, ctid.intValue());
        }
        
        try {
            Properties cryptotokenProperties = new Properties();
            cryptotokenProperties.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.toString(true));
            cryptotokenProperties.setProperty(SoftCryptoToken.NODEFAULTPWD, Boolean.TRUE.toString());
            ejbcaraws.createCryptoToken(ctname, "SoftCryptoToken", "1234", false, cryptotokenProperties);
            ctid = cryptoTokenManagementSession.getIdFromName(ctname);
            
            String keyAlias = "testWSGeneratedKeys";
            ejbcaraws.generateCryptoTokenKeys(ctname, keyAlias, "1024");
            List<String> keyAliases = cryptoTokenManagementSession.getKeyPairAliases(intAdmin, ctid.intValue());
            assertTrue(keyAliases.contains(keyAlias));
            KeyPairInfo keyInfo = cryptoTokenManagementSession.getKeyPairInfo(intAdmin, ctid.intValue(), keyAlias);
            assertEquals("RSA", keyInfo.getKeyAlgorithm());
            assertEquals("1024", keyInfo.getKeySpecification());
        } catch (RuntimeException e) {
            if(StringUtils.equals("This method can only be used in Enterprise edition.", e.getMessage())) {
                log.info("This feature is an enterprise-only feature and cannot be accessed here. Skipping this test");
            } else {
                throw e;
            }
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
        log.trace(">test72CreateCA()");
        String caname = "NewTestCAThroughWS";
        if(caSession.existsCa(caname)) {
            int caid = caSession.getCAInfo(intAdmin, caname).getCAId();
            caSession.removeCA(intAdmin, caid);
        }
        
        String ctname = caname + "CryptoToken";
        Integer ctid = cryptoTokenManagementSession.getIdFromName(ctname);
        if(ctid != null) {
            cryptoTokenManagementSession.deleteCryptoToken(intAdmin, ctid.intValue());
        }
        
        try {
            // create cryptotoken
            Properties cryptotokenProperties = new Properties();
            cryptotokenProperties.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.toString(false));
            cryptotokenProperties.setProperty(SoftCryptoToken.NODEFAULTPWD, Boolean.TRUE.toString());
            ejbcaraws.createCryptoToken(ctname, "SoftCryptoToken", "1234", false, cryptotokenProperties);
            ctid = cryptoTokenManagementSession.getIdFromName(ctname);

            // generate keys
            final String decKeyAlias = CAToken.SOFTPRIVATEDECKEYALIAS;
            ejbcaraws.generateCryptoTokenKeys(ctname, decKeyAlias, "1024");
            log.debug("test72CreateCA:Generated key " + decKeyAlias);
            final String signKeyAlias = CAToken.SOFTPRIVATESIGNKEYALIAS;
            ejbcaraws.generateCryptoTokenKeys(ctname, signKeyAlias, "1024");
            log.debug("test72CreateCA: Generated key " + signKeyAlias);
            final String testKeyAlias = "test72CreateCATestKey";
            ejbcaraws.generateCryptoTokenKeys(ctname, testKeyAlias, "1024");
            log.debug("test72CreateCA: Generated key " + testKeyAlias);
            
            // construct the ca token properties
            final Properties caTokenProperties = new Properties();
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            final String certSignValue = caTokenProperties.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING);
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, certSignValue);
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, testKeyAlias);
            log.trace("==test72CreateCA() Before Command");
            ejbcaraws.createCA(caname, "CN="+caname, "x509", "soft", "1234", caTokenProperties, ctname, testKeyAlias, 3L, null, "SHA1WithRSA", null, CAInfo.SELFSIGNED);
            log.trace("==test72CreateCA() After Command");
            CAInfo cainfo = caSession.getCAInfo(intAdmin, caname);
            assertNotNull(cainfo);
            assertEquals(caname, cainfo.getName());
            assertEquals("CN=" + caname, cainfo.getSubjectDN());
            assertEquals(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, cainfo.getCertificateProfileId());
            assertEquals(CAInfo.SELFSIGNED, cainfo.getSignedBy());
            assertEquals(CAInfo.CATYPE_X509, cainfo.getCAType());
        } catch (RuntimeException e) {
            log.trace("==test72CreateCA() RuntimeException Catch");
            if(StringUtils.equals("This method can only be used in Enterprise edition.", e.getMessage())) {
                log.info("This feature is an enterprise-only feature and cannot be accessed here. Skipping this test");
            } else {
                throw e;
            }
        } finally {
            if(caSession.existsCa(caname)) {
                int caid = caSession.getCAInfo(intAdmin, caname).getCAId();
                caSession.removeCA(intAdmin, caid);
            }
            
            ctid = cryptoTokenManagementSession.getIdFromName(ctname);
            if(ctid != null) {
                cryptoTokenManagementSession.deleteCryptoToken(intAdmin, ctid.intValue());
            }
        }
        log.trace("<test72CreateCA()");
    }

    @Test
    public void test73ManageSubjectInRole() throws Exception {
        log.trace(">test73AddSubjectToRole()");
        
        String rolename = "TestWSNewAccessRole";
        String testAdminUsername = "newWsAdminUserName";
        
        RoleData role = roleAccessSession.findRole(rolename);
        if(role != null) {
            roleManagementSession.remove(intAdmin, role);
        }
        
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
                adminUser.setStatus(UserDataVOWS.STATUS_NEW);
                adminUser.setTokenType(SecConst.TOKEN_SOFT_JKS);
                adminUser.setEndEntityProfileId(SecConst.EMPTY_ENDENTITYPROFILE);
                adminUser.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
                adminUser.setType(new EndEntityType(EndEntityTypes.ENDUSER, EndEntityTypes.ADMINISTRATOR));
                log.info("Adding new user: "+adminUser.getUsername());
                endEntityManagementSession.addUser(intAdmin, adminUser, true);
            } else {
                adminUser.setStatus(UserDataVOWS.STATUS_NEW);
                adminUser.setPassword("foo123");
                log.info("Changing user: "+adminUser.getUsername());
                endEntityManagementSession.changeUser(intAdmin, adminUser, true);
            }
            BatchCreateTool.createUser(intAdmin, "p12", adminUser.getUsername());
            adminUser = endEntityAccessSession.findUser(intAdmin, testAdminUsername);
        
            // Create a new role
            log.info("Creating new role: "+rolename);
            role = roleManagementSession.create(intAdmin, rolename);
            
            // Set access rules for the new role
            final List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
            accessRules.add(new AccessRuleData(rolename, StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, true));
            role = roleManagementSession.addAccessRulesToRole(intAdmin, role, accessRules);
            
            // Verify that there are no admins from the start
            assertTrue(role.getAccessUsers().size()==0);
        
            // Add adminUser to the new role
            ejbcaraws.addSubjectToRole(rolename, getAdminCAName(), X500PrincipalAccessMatchValue.WITH_FULLDN.name(), 
                    AccessMatchType.TYPE_EQUALCASE.name(), adminUser.getCertificateDN());
            role = roleAccessSession.findRole(rolename);
            
            // Verify the admin data
            Collection <AccessUserAspectData> admins = role.getAccessUsers().values();
            assertTrue(admins.size()==1);
            AccessUserAspectData addedAdmin = admins.iterator().next();
            assertEquals(cainfo.getCAId(), addedAdmin.getCaId().intValue());
            assertEquals(AccessMatchType.TYPE_EQUALCASE.getNumericValue(), addedAdmin.getMatchType());
            assertEquals(adminUser.getCertificateDN(), addedAdmin.getMatchValue());
            assertEquals(X500PrincipalAccessMatchValue.WITH_FULLDN.getNumericValue(), addedAdmin.getMatchWith());

            // Remove adminUser from the new role
            ejbcaraws.removeSubjectFromRole(rolename, getAdminCAName(), X500PrincipalAccessMatchValue.WITH_FULLDN.name(), 
                    AccessMatchType.TYPE_EQUALCASE.name(), adminUser.getCertificateDN());
            role = roleAccessSession.findRole(rolename);            
            assertTrue(role.getAccessUsers().values().size()==0);
            
        } catch (RuntimeException e) {
            if(StringUtils.equals("This method can only be used in Enterprise edition.", e.getMessage())) {
                log.info("This feature is an enterprise-only feature and cannot be accessed here. Skipping this test");
            } else {
                throw e;
            }
        } finally {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, testAdminUsername, RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN);
            if(roleAccessSession.findRole(rolename)!=null) {
                roleManagementSession.remove(intAdmin, roleAccessSession.findRole(rolename));
            }
        }
        log.trace("<test73AddSubjectToRole()");
    }

    
    private void testCertificateRequestWithEeiDnOverride(boolean allowDNOverrideByEndEntityInformation, boolean useCsr, String requestedSubjectDN, String expectedSubjectDN) throws Exception {
        if (certificateProfileSession.getCertificateProfileId(WS_TEST_CERTIFICATE_PROFILE_NAME) != 0) {
            certificateProfileSession.removeCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME);
        }
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setAllowDNOverrideByEndEntityInformation(allowDNOverrideByEndEntityInformation);
        certificateProfileSession.addCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME, profile);
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
            userData.setStatus(UserDataVOWS.STATUS_NEW);
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
            } catch (NotFoundException e) {
                // Ignore
            }
        } finally {
            if (certificateProfileSession.getCertificateProfileId(WS_TEST_CERTIFICATE_PROFILE_NAME) != 0) {
                certificateProfileSession.removeCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME);
            }
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
        userData.setStatus(UserDataVOWS.STATUS_NEW);
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
        } catch (NotFoundException e) {
            // Ignore
        }
    }

    /**
     * Creates a "hardtoken" with certficates.
     */
    private void createHardToken(String username, String caName, String serialNumber) throws Exception {
        GlobalConfiguration gc = (GlobalConfiguration) raAdminSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        boolean originalProfileSetting = gc.getEnableEndEntityProfileLimitations();
        gc.setEnableEndEntityProfileLimitations(false);
        raAdminSession.saveConfiguration(intAdmin, gc);
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
        tokenUser1.setStatus(UserDataVOWS.STATUS_NEW);
        tokenUser1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        tokenUser1.setEndEntityProfileName("EMPTY");
        tokenUser1.setCertificateProfileName("ENDUSER");
        KeyPair basickeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        PKCS10CertificationRequest basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", CertTools.stringToBcX500Name("CN=NOTUSED"), basickeys
                .getPublic(), new DERSet(), basickeys.getPrivate(), null);
        ArrayList<TokenCertificateRequestWS> requests = new ArrayList<TokenCertificateRequestWS>();
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
        certificateProfileSession.removeCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME);
        gc.setEnableEndEntityProfileLimitations(originalProfileSetting);
        raAdminSession.saveConfiguration(intAdmin, gc);
    } // createHardToken

    /**
     * Create a user a generate cert.
     */
    private X509Certificate createUserAndCert(String username, int caID) throws Exception {
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, caID, null, null, new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword(PASSWORD);
        endEntityManagementSession.addUser(intAdmin, userdata, true);
        File tmpfile = File.createTempFile("ejbca", "p12");
        BatchCreateTool.createAllNew(intAdmin, tmpfile.getParent());
        Collection<Certificate> userCerts = certificateStoreSession.findCertificatesByUsername(username);
        assertTrue(userCerts.size() == 1);
        return (X509Certificate) userCerts.iterator().next();
    }

}
