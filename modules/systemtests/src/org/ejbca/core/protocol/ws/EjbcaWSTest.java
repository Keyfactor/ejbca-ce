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

import java.io.File;
import java.net.URL;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import javax.xml.namespace.QName;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalTest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.hardtoken.HardTokenConstants;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
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
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.keystore.KeyTools;
import org.jboss.logging.Logger;

/**
 * This test uses remote EJB calls to setup the environment.
 * 
 * @version $Id$
 */
public class EjbcaWSTest extends CommonEjbcaWS {

    private static final Logger log = Logger.getLogger(EjbcaWSTest.class);

    private ApprovalSessionRemote approvalSessionRemote = InterfaceCache.getApprovalSession();
    private CAAdminSessionRemote caAdminSessionRemote = InterfaceCache.getCAAdminSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private HardTokenSessionRemote hardTokenSessionRemote = InterfaceCache.getHardTokenSession();
    private RaAdminSessionRemote raAdminSession = InterfaceCache.getRAAdminSession();
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

    public void test00SetupAccessRights() throws Exception {
        super.setupAccessRights();
    }

    public void test01EditUser() throws Exception {
        setUpAdmin();
        super.editUser();
    }

    public void test02FindUser() throws Exception {
        setUpAdmin();
        findUser();
    }

    public void test03_1GeneratePkcs10() throws Exception {
        setUpAdmin();
        generatePkcs10();
    }

    public void test03_2GenerateCrmf() throws Exception {
        setUpAdmin();
        generateCrmf();
    }

    public void test03_3GenerateSpkac() throws Exception {
        setUpAdmin();
        generateSpkac();
    }

    public void test03_4GeneratePkcs10Request() throws Exception {
        setUpAdmin();
        generatePkcs10Request();
    }

    public void test03_5CertificateRequest() throws Exception {
        setUpAdmin();
        certificateRequest();
    }

    public void test03_6EnforcementOfUniquePublicKeys() throws Exception {
        setUpAdmin();
        enforcementOfUniquePublicKeys();
    }

    public void test03_6EnforcementOfUniqueSubjectDN() throws Exception {
        setUpAdmin();
        enforcementOfUniqueSubjectDN();
    }

    public void test04GeneratePkcs12() throws Exception {
        setUpAdmin();
        generatePkcs12();
    }

    public void test05FindCerts() throws Exception {
        setUpAdmin();
        findCerts();
    }

    public void test06RevokeCert() throws Exception {
        setUpAdmin();
        revokeCert();
    }

    public void test07RevokeToken() throws Exception {
        setUpAdmin();
        revokeToken();
    }

    public void test08CheckRevokeStatus() throws Exception {
        setUpAdmin();
        checkRevokeStatus();
    }

    public void test09Utf8() throws Exception {
        setUpAdmin();
        utf8();
    }

    public void test10GetLastCertChain() throws Exception {
        setUpAdmin();
        getLastCertChain();
    }

    public void test11RevokeUser() throws Exception {
        setUpAdmin();
        revokeUser();
    }

    public void test12IsAuthorized() throws Exception {
        setUpAdmin();

        // This is a superadmin keystore, improve in the future
        assertTrue(ejbcaraws.isAuthorized(AccessRulesConstants.ROLE_SUPERADMINISTRATOR));
    }

    public void test13genTokenCertificates() throws Exception {
        setUpAdmin();
        genTokenCertificates(false);
    }

    public void test14getExistsHardToken() throws Exception {
        setUpAdmin();
        getExistsHardToken();
    }

    public void test15getHardTokenData() throws Exception {
        setUpAdmin();
        getHardTokenData("12345678", false);
    }

    public void test16getHardTokenDatas() throws Exception {
        setUpAdmin();
        getHardTokenDatas();
    }

    public void test17CustomLog() throws Exception {
        setUpAdmin();
        customLog();
    }

    public void test18GetCertificate() throws Exception {
        setUpAdmin();
        getCertificate();
    }

    public void test19RevocationApprovals() throws Exception {
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
            caID = RevocationApprovalTest.createApprovalCA(intAdmin, caname, CAInfo.REQ_APPROVAL_REVOCATION, caAdminSessionRemote);
            X509Certificate adminCert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(intAdmin, APPROVINGADMINNAME).iterator().next();
            Admin approvingAdmin = new Admin(adminCert, APPROVINGADMINNAME, null);
            try {
                X509Certificate cert = createUserAndCert(username, caID);
                String issuerdn = cert.getIssuerDN().toString();
                String serno = cert.getSerialNumber().toString(16);
                // revoke via WS and verify response
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (WaitingForApprovalException_Exception e1) {
                }
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (ApprovalException_Exception e1) {
                }
                RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
                assertNotNull(revokestatus);
                assertTrue(revokestatus.getReason() == RevokedCertInfo.NOT_REVOKED);
                // Approve revocation and verify success
                approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD,
                        ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, certificateStoreSession, approvalSessionRemote, caID);
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
                        certificateStoreSession, approvalSessionRemote, caID);
                // Revoke user
                try {
                    ejbcaraws.revokeUser(username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD, false);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (WaitingForApprovalException_Exception e) {
                }
                try {
                    ejbcaraws.revokeUser(username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD, false);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (ApprovalException_Exception e) {
                }
                // Approve revocation and verify success
                approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD,
                        ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY, certificateStoreSession, approvalSessionRemote, caID);
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
                    ejbcaraws.revokeToken(TOKENSERIALNUMBER, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (WaitingForApprovalException_Exception e) {
                }
                try {
                    ejbcaraws.revokeToken(TOKENSERIALNUMBER, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (ApprovalException_Exception e) {
                }
                // Approve actions and verify success
                approveRevocation(intAdmin, approvingAdmin, TOKENUSERNAME, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD,
                        ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, certificateStoreSession, approvalSessionRemote, caID);
            } finally {
                hardTokenSessionRemote.removeHardToken(intAdmin, TOKENSERIALNUMBER);
            }
        } finally {
            // Nuke CA
            try {
                caAdminSessionRemote.revokeCA(intAdmin, caID, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
            } finally {
                caAdminSessionRemote.removeCA(intAdmin, caID);
            }
        }
    }

    public void test20KeyRecoverNewest() throws Exception {
        setUpAdmin();
        keyRecover();
    }

    public void test21GetAvailableCAs() throws Exception {
        setUpAdmin();
        getAvailableCAs();
    }

    public void test22GetAuthorizedEndEntityProfiles() throws Exception {
        setUpAdmin();
        getAuthorizedEndEntityProfiles();
    }

    public void test23GetAvailableCertificateProfiles() throws Exception {
        setUpAdmin();
        getAvailableCertificateProfiles();
    }

    public void test24GetAvailableCAsInProfile() throws Exception {
        setUpAdmin();
        getAvailableCAsInProfile();
    }

    public void test25GreateCRL() throws Exception {
        setUpAdmin();
        createCRL();
    }

    public void test26_1CvcRequestRSA() throws Exception {
        setUpAdmin();
        cvcRequest("CN=WSCVCA,C=SE", "WSTESTCVCA", "CN=WSDVCA,C=SE", "WSTESTDVCA", CA1_WSTESTUSER1CVCRSA, "1024", AlgorithmConstants.KEYALGORITHM_RSA,
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1);
    }

    public void test26_2CleanCvcRequestRSA() throws Exception {
        // Remove the CAs
        deleteCVCCA("CN=WSCVCA,C=SE", "CN=WSDVCA,C=SE");
    }

    public void test26_3CvcRequestECDSA() throws Exception {
        setUpAdmin();
        cvcRequest("CN=WSCVCAEC,C=SE", "WSTESTCVCAEC", "CN=WSDVCAEC,C=SE", "WSTESTDVCAEC", CA2_WSTESTUSER1CVCEC, "secp256r1",
                AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
    }

    public void test26_4CleanCvcRequestECDSA() throws Exception {
        // Remove the CAs
        deleteCVCCA("CN=WSCVCAEC,C=SE", "CN=WSDVCAEC,C=SE");
    }

    public void test27EjbcaVersion() throws Exception {
        setUpAdmin();
        ejbcaVersion();
    }

    public void test29ErrorOnEditUser() throws Exception {
        setUpAdmin();
        errorOnEditUser();
    }

    public void test30ErrorOnGeneratePkcs10() throws Exception {
        setUpAdmin();
        errorOnGeneratePkcs10();
    }

    public void test31ErrorOnGeneratePkcs12() throws Exception {
        setUpAdmin();
        errorOnGeneratePkcs12();
    }

    public void test32OperationOnNonexistingCA() throws Exception {
        setUpAdmin();
        operationOnNonexistingCA();
    }

    public void test33CheckQueueLength() throws Exception {
        setUpAdmin();
        checkQueueLength();
    }

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

    public void test35CleanUpCACertRequest() throws Exception {
    	log.trace(">test35CleanUpCACertRequest()");
        setUpAdmin();
        super.cleanUpCACertRequest();
        log.trace("<test35CleanUpCACertRequest()");
    }

    /**
     * Simulate a simple SQL injection by sending the illegal char "'".
     * 
     * @throws Exception
     */
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
    public void testCertificateRequestWithSpecialChars01() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=foo\\+bar\\\"\\,, C=SE", "CN=test" + rnd + ",O=foo\\+bar\\\"\\,,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    public void testCertificateRequestWithSpecialChars02() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=foo;bar\\;123, C=SE", "CN=test" + rnd + ",O=foo/bar\\;123,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    public void testCertificateRequestWithSpecialChars03() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=foo+bar\\+123, C=SE", "CN=test" + rnd + ",O=foo\\+bar\\+123,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    public void testCertificateRequestWithSpecialChars04() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=foo\\=bar, C=SE", "CN=test" + rnd + ",O=foo\\=bar,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    public void testCertificateRequestWithSpecialChars05() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=\"foo=bar, C=SE\"", "CN=test" + rnd + ",O=foo\\=bar\\, C\\=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    public void testCertificateRequestWithSpecialChars06() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=\"foo+b\\+ar, C=SE\"", "CN=test" + rnd + ",O=foo\\+b\\\\\\+ar\\, C\\=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    public void testCertificateRequestWithSpecialChars07() throws Exception {
        setUpAdmin();
        long rnd = new SecureRandom().nextLong();
        testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=\\\"foo+b\\+ar\\, C=SE\\\"", "CN=test" + rnd + ",O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"");
    }

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
        raAdminSession.saveGlobalConfiguration(intAdmin, gc);
        if (certificateStoreSession.getCertificateProfileId(intAdmin, "WSTESTPROFILE") != 0) {
            certificateStoreSession.removeCertificateProfile(intAdmin, "WSTESTPROFILE");
        }
        CertificateProfile profile = new EndUserCertificateProfile();
        profile.setAllowValidityOverride(true);
        certificateStoreSession.addCertificateProfile(intAdmin, "WSTESTPROFILE", profile);
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
        certificateStoreSession.removeCertificateProfile(intAdmin, "WSTESTPROFILE");
        gc.setEnableEndEntityProfileLimitations(originalProfileSetting);
        raAdminSession.saveGlobalConfiguration(intAdmin, gc);
    } // createHardToken

    /**
     * Create a user a generate cert.
     */
    private X509Certificate createUserAndCert(String username, int caID) throws Exception {
        UserDataVO userdata = new UserDataVO(username, "CN=" + username, caID, null, null, 1, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        userAdminSession.addUser(intAdmin, userdata, true);
        BatchMakeP12 makep12 = new BatchMakeP12();
        File tmpfile = File.createTempFile("ejbca", "p12");
        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createAllNew();
        Collection<X509Certificate> userCerts = certificateStoreSession.findCertificatesByUsername(intAdmin, username);
        assertTrue(userCerts.size() == 1);
        return userCerts.iterator().next();
    }

}
