/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.net.URL;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;

import javax.security.auth.x500.X500Principal;
import javax.xml.namespace.QName;

import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.cesecore.ErrorCode;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalTest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.hardtoken.HardTokenConstants;
import org.ejbca.core.protocol.ws.client.gen.AlreadyRevokedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
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
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.InterfaceCache;
import org.junit.AfterClass;
import org.junit.Test;

/**
 * This test uses remote EJB calls to setup the environment.
 * 
 * @version $Id$
 */
public class EjbcaWSTest extends CommonEjbcaWS {

    private static final Logger log = Logger.getLogger(EjbcaWSTest.class);

    private ApprovalExecutionSessionRemote approvalExecutionSession = InterfaceCache.getApprovalExecutionSession();
    private ApprovalSessionRemote approvalSession = InterfaceCache.getApprovalSession();
    private CAAdminSessionRemote caAdminSessionRemote = InterfaceCache.getCAAdminSession();
    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private CertificateProfileSessionRemote certificateProfileSession = InterfaceCache.getCertificateProfileSession();
    private EndEntityAccessSessionRemote endEntityAccessSession = JndiHelper.getRemoteSession(EndEntityAccessSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = InterfaceCache.getEndEntityProfileSession();
    private HardTokenSessionRemote hardTokenSessionRemote = InterfaceCache.getHardTokenSession();
    private GlobalConfigurationSessionRemote raAdminSession = InterfaceCache.getGlobalConfigurationSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();

    private void setUpAdmin() throws Exception {
        super.setUp();
        CryptoProviderTools.installBCProvider();
        if (new File("p12/wstest.jks").exists()) {
            String urlstr = "https://" + hostname + ":" + httpsPort + "/ejbca/ejbcaws/ejbcaws?wsdl";
            log.info("Contacting webservice at " + urlstr);

            System.setProperty("javax.net.ssl.trustStore", "p12/wstest.jks");
            System.setProperty("javax.net.ssl.trustStorePassword", "foo123");
            System.setProperty("javax.net.ssl.keyStore", "p12/wstest.jks");
            System.setProperty("javax.net.ssl.keyStorePassword", "foo123");

            QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
            EjbcaWSService service = new EjbcaWSService(new URL(urlstr), qname);
            super.ejbcaraws = service.getEjbcaWSPort();
        }
    }

    @Test
    public void test00SetupAccessRights() throws Exception {
        super.setupAccessRights();
    }

    @Test
    public void test01EditUser() throws Exception {
        setUpAdmin();
        super.editUser();
    }

    @Test
    public void test02FindUser() throws Exception {
        setUpAdmin();
        findUser();
    }

    @Test
    public void test03_1GeneratePkcs10() throws Exception {
        setUpAdmin();
        generatePkcs10();
    }

    @Test
    public void test03_2GenerateCrmf() throws Exception {
        setUpAdmin();
        generateCrmf();
    }

    @Test
    public void test03_3GenerateSpkac() throws Exception {
        setUpAdmin();
        generateSpkac();
    }

    @Test
    public void test03_4GeneratePkcs10Request() throws Exception {
        setUpAdmin();
        generatePkcs10Request();
    }

    @Test
    public void test03_5CertificateRequest() throws Exception {
        setUpAdmin();
        certificateRequest();
    }

    @Test
    public void test03_6EnforcementOfUniquePublicKeys() throws Exception {
        setUpAdmin();
        enforcementOfUniquePublicKeys();
    }

    @Test
    public void test03_6EnforcementOfUniqueSubjectDN() throws Exception {
        setUpAdmin();
        enforcementOfUniqueSubjectDN();
    }

    @Test
    public void test04GeneratePkcs12() throws Exception {
        setUpAdmin();
        generatePkcs12();
    }

    @Test
    public void test05FindCerts() throws Exception {
        setUpAdmin();
        findCerts();
    }

    @Test
    public void test06RevokeCert() throws Exception {
        setUpAdmin();
        revokeCert();
    }

    @Test
    public void test07RevokeToken() throws Exception {
        setUpAdmin();
        revokeToken();
    }

    @Test
    public void test08CheckRevokeStatus() throws Exception {
        setUpAdmin();
        checkRevokeStatus();
    }

    @Test
    public void test09Utf8() throws Exception {
        setUpAdmin();
        utf8();
    }

    @Test
    public void test10GetLastCertChain() throws Exception {
        setUpAdmin();
        getLastCertChain();
    }

    @Test
    public void test11RevokeUser() throws Exception {
        setUpAdmin();
        revokeUser();
    }

    @Test
    public void test12IsAuthorized() throws Exception {
        setUpAdmin();

        // This is a superadmin keystore, improve in the future
        assertTrue(ejbcaraws.isAuthorized(AccessRulesConstants.ROLE_SUPERADMINISTRATOR));
    }

    @Test
    public void test13genTokenCertificates() throws Exception {
        setUpAdmin();
        genTokenCertificates(false);
    }

    @Test
    public void test14getExistsHardToken() throws Exception {
        setUpAdmin();
        getExistsHardToken();
    }

    @Test
    public void test15getHardTokenData() throws Exception {
        setUpAdmin();
        getHardTokenData("12345678", false);
    }

    @Test
    public void test16getHardTokenDatas() throws Exception {
        setUpAdmin();
        getHardTokenDatas();
    }

    @Test
    public void test17CustomLog() throws Exception {
        setUpAdmin();
        customLog();
    }

    @Test
    public void test18GetCertificate() throws Exception {
        setUpAdmin();
        getCertificate();
    }

    @Test
    public void test19RevocationApprovals() throws Exception {
    	log.trace(">test19RevocationApprovals");
        setUpAdmin();
        final String APPROVINGADMINNAME = "superadmin";
        final String TOKENSERIALNUMBER = "42424242";
        final String TOKENUSERNAME = "WSTESTTOKENUSER3";
        final String ERRORNOTSENTFORAPPROVAL = "The request was never sent for approval.";
        final String ERRORNOTSUPPORTEDSUCCEEDED = "Reactivation of users is not supported, but succeeded anyway.";

        // Generate random username and CA name
        String randomPostfix = Integer.toString(SecureRandom.getInstance("SHA1PRNG").nextInt(999999));
        String caname = "wsRevocationCA" + randomPostfix;
        String username = "wsRevocationUser" + randomPostfix;
        int caID = -1;
        try {
            caID = RevocationApprovalTest.createApprovalCA(intAdmin, caname, CAInfo.REQ_APPROVAL_REVOCATION, caAdminSessionRemote, caSession);
            X509Certificate adminCert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(APPROVINGADMINNAME).iterator().next();
            Set<X509Certificate> credentials = new HashSet<X509Certificate>();
            credentials.add(adminCert);
            Set<X500Principal> principals = new HashSet<X500Principal>();
            principals.add(adminCert.getSubjectX500Principal());
            AuthenticationToken approvingAdmin = new X509CertificateAuthenticationToken(principals, credentials);
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
                userAdminSession.deleteUser(intAdmin, username);
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
            }
        }
    	log.trace("<test19RevocationApprovals");
    }

    @Test
    public void test20KeyRecoverNewest() throws Exception {
        setUpAdmin();
        keyRecover();
    }

    @Test
    public void test21GetAvailableCAs() throws Exception {
        setUpAdmin();
        getAvailableCAs();
    }

    @Test
    public void test22GetAuthorizedEndEntityProfiles() throws Exception {
        setUpAdmin();
        getAuthorizedEndEntityProfiles();
    }

    @Test
    public void test23GetAvailableCertificateProfiles() throws Exception {
        setUpAdmin();
        getAvailableCertificateProfiles();
    }

    @Test
    public void test24GetAvailableCAsInProfile() throws Exception {
        setUpAdmin();
        getAvailableCAsInProfile();
    }
    
    @Test
    public void test25GreateCRL() throws Exception {
        setUpAdmin();
        createCRL();
    }

    
    @Test
    public void test26_1CvcRequestRSA() throws Exception {
        setUpAdmin();
        cvcRequest("CN=WSCVCA,C=SE", "WSTESTCVCA", "CN=WSDVCA,C=SE", "WSTESTDVCA", CA1_WSTESTUSER1CVCRSA, "1024", AlgorithmConstants.KEYALGORITHM_RSA,
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1);
    }
    
    @Test
    public void test26_2CleanCvcRequestRSA() throws Exception {
        // Remove the CAs
        deleteCVCCA("CN=WSCVCA,C=SE", "CN=WSDVCA,C=SE");
    }

    @Test
    public void test26_3CvcRequestECDSA() throws Exception {
        setUpAdmin();
        cvcRequest("CN=WSCVCAEC,C=SE", "WSTESTCVCAEC", "CN=WSDVCAEC,C=SE", "WSTESTDVCAEC", CA2_WSTESTUSER1CVCEC, "secp256r1",
                AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
    }

    @Test
    public void test26_4CleanCvcRequestECDSA() throws Exception {
        // Remove the CAs
        deleteCVCCA("CN=WSCVCAEC,C=SE", "CN=WSDVCAEC,C=SE");
    }

    @Test
    public void test27EjbcaVersion() throws Exception {
        setUpAdmin();
        ejbcaVersion();
    }

    @Test
    public void test29ErrorOnEditUser() throws Exception {
        setUpAdmin();
        errorOnEditUser();
    }

    @Test
    public void test30ErrorOnGeneratePkcs10() throws Exception {
        setUpAdmin();
        errorOnGeneratePkcs10();
    }

    @Test
    public void test31ErrorOnGeneratePkcs12() throws Exception {
        setUpAdmin();
        errorOnGeneratePkcs12();
    }

    @Test
    public void test32OperationOnNonexistingCA() throws Exception {
        setUpAdmin();
        operationOnNonexistingCA();
    }

    @Test
    public void test33CheckQueueLength() throws Exception {
        setUpAdmin();
        checkQueueLength();
    }

    @Test
    public void test34_1CaRenewCertRequestRSA() throws Exception {
    	log.trace(">test34_1CaRenewCertRequestRSA()");
        setUpAdmin();
        final String cvcaMnemonic = "CVCAEXEC";
        final String dvcaName = "WSTESTDVCARSASIGNEDBYEXTERNAL";
        final String dvcaMnemonic = "WSDVEXECR";
        final String keyspec = "1024";
        final String keyalg = AlgorithmConstants.KEYALGORITHM_RSA;
        final String signalg = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        super.caRenewCertRequest(cvcaMnemonic, dvcaName, dvcaMnemonic, keyspec, keyalg, signalg);
        log.trace("<test34_1CaRenewCertRequestRSA()");
    }

    @Test
    public void test34_2CaRenewCertRequestECC() throws Exception {
    	log.trace(">test34_2CaRenewCertRequestECC()");
        setUpAdmin();
        final String cvcaMnemonic = "CVCAEXEC";
        final String dvcaName = "WSTESTDVCAECCSIGNEDBYEXTERNAL";
        final String dvcaMnemonic = "WSDVEXECE";
        final String keyspec = "secp256r1";
        final String keyalg = AlgorithmConstants.KEYALGORITHM_ECDSA;
        final String signalg = AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
		CardVerifiableCertificate cvcacert = super.caRenewCertRequest(cvcaMnemonic, dvcaName, dvcaMnemonic, keyspec, keyalg, signalg);
		super.caMakeRequestAndFindCA(dvcaName, cvcacert);
		log.trace("<test34_2CaRenewCertRequestECC()");
    }

    @Test
    public void test35CleanUpCACertRequest() throws Exception {
    	log.trace(">test35CleanUpCACertRequest()");
        setUpAdmin();
        super.cleanUpCACertRequest();
        log.trace("<test35CleanUpCACertRequest()");
    }

    /** In EJBCA 4.0.0 we changed the date format to ISO 8601. This verifies the that we still accept old requests, but returns UserDataVOWS objects using the new DateFormat 
     * @throws AuthorizationDeniedException */
    @Test
    public void test36EjbcaWsHelperTimeFormatConversion() throws CADoesntExistsException, ClassCastException, EjbcaException, AuthorizationDeniedException {
    	log.trace(">test36EjbcaWsHelperTimeFormatConversion()");
    	final EjbcaWSHelper ejbcaWsHelper = new EjbcaWSHelper(null, null, caAdminSessionRemote, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSessionRemote, userAdminSession);
		final Date nowWithOutSeconds = new Date((new Date().getTime()/60000)*60000);	// To avoid false negatives.. we will loose precision when we convert back and forth..
    	final String oldTimeFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US).format(nowWithOutSeconds);
    	final String newTimeFormatStorage = FastDateFormat.getInstance("yyyy-MM-dd HH:mm", TimeZone.getTimeZone("UTC")).format(nowWithOutSeconds);
    	final String newTimeFormatRequest = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZZ", TimeZone.getTimeZone("CEST")).format(nowWithOutSeconds);
    	final String newTimeFormatResponse = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZZ", TimeZone.getTimeZone("UTC")).format(nowWithOutSeconds);
    	final String relativeTimeFormat = "0123:12:31";
    	log.debug("oldTimeFormat=" + oldTimeFormat);
    	log.debug("newTimeFormatStorage=" + newTimeFormatStorage);
    	log.debug("newTimeFormatRequest=" + newTimeFormatRequest);
    	// Convert from UserDataVOWS with US Locale DateFormat to UserDataVO
    	final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs = new org.ejbca.core.protocol.ws.objects.UserDataVOWS("username", "password", false, "CN=User U", "CA1", null, null, 10, "P12", "EMPTY", "ENDUSER", null);
    	userDataVoWs.setStartTime(oldTimeFormat);
    	userDataVoWs.setEndTime(oldTimeFormat);
    	final EndEntityInformation userDataVo1 = ejbcaWsHelper.convertUserDataVOWS(intAdmin, userDataVoWs);
    	assertEquals("CUSTOM_STARTTIME in old format was not correctly handled (VOWS to VO).", newTimeFormatStorage, userDataVo1.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
    	assertEquals("CUSTOM_ENDTIME in old format was not correctly handled (VOWS to VO).", newTimeFormatStorage, userDataVo1.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
    	// Convert from UserDataVOWS with standard DateFormat to UserDataVO
    	userDataVoWs.setStartTime(newTimeFormatRequest);
    	userDataVoWs.setEndTime(newTimeFormatRequest);
    	final EndEntityInformation userDataVo2 = ejbcaWsHelper.convertUserDataVOWS(intAdmin, userDataVoWs);
    	assertEquals("ExtendedInformation.CUSTOM_STARTTIME in new format was not correctly handled.", newTimeFormatStorage, userDataVo2.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
    	assertEquals("ExtendedInformation.CUSTOM_ENDTIME in new format was not correctly handled.", newTimeFormatStorage, userDataVo2.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
    	// Convert from UserDataVOWS with relative date format to UserDataVO
    	userDataVoWs.setStartTime(relativeTimeFormat);
    	userDataVoWs.setEndTime(relativeTimeFormat);
    	final EndEntityInformation userDataVo3 = ejbcaWsHelper.convertUserDataVOWS(intAdmin, userDataVoWs);
    	assertEquals("ExtendedInformation.CUSTOM_STARTTIME in relative format was not correctly handled.", relativeTimeFormat, userDataVo3.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
    	assertEquals("ExtendedInformation.CUSTOM_ENDTIME in relative format was not correctly handled.", relativeTimeFormat, userDataVo3.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
    	// Convert from UserDataVO with standard DateFormat to UserDataVOWS
    	final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs1 = ejbcaWsHelper.convertUserDataVO(intAdmin, userDataVo1);
    	// We expect that the server will respond using UTC
    	assertEquals("CUSTOM_STARTTIME in new format was not correctly handled (VO to VOWS).", newTimeFormatResponse, userDataVoWs1.getStartTime());
    	assertEquals("CUSTOM_ENDTIME in new format was not correctly handled (VO to VOWS).", newTimeFormatResponse, userDataVoWs1.getEndTime());
    	// Convert from UserDataVO with relative date format to UserDataVOWS
    	final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs3 = ejbcaWsHelper.convertUserDataVO(intAdmin, userDataVo3);
    	assertEquals("CUSTOM_STARTTIME in relative format was not correctly handled (VO to VOWS).", relativeTimeFormat, userDataVoWs3.getStartTime());
    	assertEquals("CUSTOM_ENDTIME in relative format was not correctly handled (VO to VOWS).", relativeTimeFormat, userDataVoWs3.getEndTime());
    	// Try some invalid start time date format
    	userDataVoWs.setStartTime("12:32 2011-02-28");	// Invalid
    	userDataVoWs.setEndTime("2011-02-28 12:32:00+00:00");	// Valid
    	try {
        	ejbcaWsHelper.convertUserDataVOWS(intAdmin, userDataVoWs);
        	fail("Conversion of illegal time format did not generate exception.");
    	} catch (EjbcaException e) {
    		assertEquals("Unexpected error code in exception.", ErrorCode.FIELD_VALUE_NOT_VALID, e.getErrorCode());
    	}
    	// Try some invalid end time date format
    	userDataVoWs.setStartTime("2011-02-28 12:32:00+00:00");	// Valid
    	userDataVoWs.setEndTime("12:32 2011-02-28");	// Invalid
    	try {
        	ejbcaWsHelper.convertUserDataVOWS(intAdmin, userDataVoWs);
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
    public void testEvilFind01() throws Exception {
        log.trace(">testEvilFind01()");
        setUpAdmin();
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
    public void testCertificateRequestWithSpecialChars01() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=foo\\+bar\\\"\\,, C=SE", "CN=test" + rnd + ",O=foo\\+bar\\\"\\,,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void testCertificateRequestWithSpecialChars02() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=foo;bar\\;123, C=SE", "CN=test" + rnd + ",O=foo/bar\\;123,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void testCertificateRequestWithSpecialChars03() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=foo+bar\\+123, C=SE", "CN=test" + rnd + ",O=foo\\+bar\\+123,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void testCertificateRequestWithSpecialChars04() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=foo\\=bar, C=SE", "CN=test" + rnd + ",O=foo\\=bar,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void testCertificateRequestWithSpecialChars05() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=\"foo=bar, C=SE\"", "CN=test" + rnd + ",O=foo\\=bar\\, C\\=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void testCertificateRequestWithSpecialChars06() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=\"foo+b\\+ar, C=SE\"", "CN=test" + rnd + ",O=foo\\+b\\\\\\+ar\\, C\\=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void testCertificateRequestWithSpecialChars07() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=\\\"foo+b\\+ar\\, C=SE\\\"", "CN=test" + rnd + ",O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"");
    }

    @AfterClass
    public void test99cleanUpAdmins() throws Exception {
        super.cleanUpAdmins();
    }

    private void testCertificateRequestWithSpecialChars(String requestedSubjectDN, String expectedSubjectDN) throws Exception {
        String userName = "wsSpecialChars" + new SecureRandom().nextLong();
        final UserDataVOWS userData = new UserDataVOWS();
        userData.setUsername(userName);
        userData.setPassword("foo123");
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
        java.security.KeyStore keyStore = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo123");
        assertNotNull(keyStore);
        Enumeration<String> en = keyStore.aliases();
        String alias = en.nextElement();
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

        String resultingSubjectDN = cert.getSubjectDN().toString();
        assertEquals(requestedSubjectDN + " was transformed into " + resultingSubjectDN + " (not the expected " + expectedSubjectDN + ")", expectedSubjectDN,
                resultingSubjectDN);
    }

    /**
     * Creates a "hardtoken" with certficates.
     */
    private void createHardToken(String username, String caName, String serialNumber) throws Exception {
        GlobalConfiguration gc = raAdminSession.getCachedGlobalConfiguration(intAdmin);
        boolean originalProfileSetting = gc.getEnableEndEntityProfileLimitations();
        gc.setEnableEndEntityProfileLimitations(false);
        raAdminSession.saveGlobalConfigurationRemote(intAdmin, gc);
        if (certificateProfileSession.getCertificateProfileId("WSTESTPROFILE") != 0) {
            certificateProfileSession.removeCertificateProfile(intAdmin, "WSTESTPROFILE");
        }
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setAllowValidityOverride(true);
        certificateProfileSession.addCertificateProfile(intAdmin, "WSTESTPROFILE", profile);
        UserDataVOWS tokenUser1 = new UserDataVOWS();
        tokenUser1.setUsername(username);
        tokenUser1.setPassword("foo123");
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
        PKCS10CertificationRequest basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("CN=NOTUSED"), basickeys
                .getPublic(), new DERSet(), basickeys.getPrivate());
        ArrayList<TokenCertificateRequestWS> requests = new ArrayList<TokenCertificateRequestWS>();
        TokenCertificateRequestWS tokenCertReqWS = new TokenCertificateRequestWS();
        tokenCertReqWS.setCAName(caName);
        tokenCertReqWS.setCertificateProfileName("WSTESTPROFILE");
        tokenCertReqWS.setValidityIdDays("1");
        tokenCertReqWS.setPkcs10Data(basicpkcs10.getDEREncoded());
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
        certificateProfileSession.removeCertificateProfile(intAdmin, "WSTESTPROFILE");
        gc.setEnableEndEntityProfileLimitations(originalProfileSetting);
        raAdminSession.saveGlobalConfigurationRemote(intAdmin, gc);
    } // createHardToken

    /**
     * Create a user a generate cert.
     */
    private X509Certificate createUserAndCert(String username, int caID) throws Exception {
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, caID, null, null, 1, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        userAdminSession.addUser(intAdmin, userdata, true);
        BatchMakeP12 makep12 = new BatchMakeP12();
        File tmpfile = File.createTempFile("ejbca", "p12");
        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createAllNew();
        Collection<Certificate> userCerts = certificateStoreSession.findCertificatesByUsername(username);
        assertTrue(userCerts.size() == 1);
        return (X509Certificate) userCerts.iterator().next();
    }

}
