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
import java.io.FileInputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.authorization.AdminEntitySessionRemote;
import org.ejbca.core.ejb.authorization.AuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.GenerateTokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ViewHardTokenDataApprovalRequest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.protocol.ws.client.gen.ApprovalRequestExecutionException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;

/**
 * 
 * @version $Id$
 */
public class EjbcaWSNonAdminTest extends CommonEjbcaWS {

    private static final Logger log = Logger.getLogger(EjbcaWSNonAdminTest.class);

    private static String adminusername1 = null;
    private static X509Certificate admincert1 = null;
    private static Admin admin1 = null;
    private static int caid;
    private static GlobalConfiguration gc = null;

    private List<AdminEntity> adminEntities;
    private Admin intadmin = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
    private Admin reqadmin;

    private CAAdminSessionRemote caAdminSessionRemote = InterfaceCache.getCAAdminSession();
    private ApprovalExecutionSessionRemote approvalExecutionSession = InterfaceCache.getApprovalExecutionSession();
    private ApprovalSessionRemote approvalSession = InterfaceCache.getApprovalSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private HardTokenSessionRemote hardTokenSessionRemote = InterfaceCache.getHardTokenSession();
    private GlobalConfigurationSessionRemote globalConfigurationSession = InterfaceCache.getGlobalConfigurationSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private AuthorizationSessionRemote authorizationSession = InterfaceCache.getAuthorizationSession();
    private AdminEntitySessionRemote adminEntitySession = InterfaceCache.getAdminEntitySession();
    
    public void test00SetupAccessRights() throws Exception {
        super.setupAccessRights();
        gc = globalConfigurationSession.getCachedGlobalConfiguration(intadmin);
        assertNotNull("Unable to fetch GlobalConfiguration.");
    }

    private void setUpNonAdmin() throws Exception {
        super.setUp();
        CryptoProviderTools.installBCProvider();
        if (new File("p12/wsnonadmintest.jks").exists()) {
            String urlstr = "https://" + hostname + ":" + httpsPort + "/ejbca/ejbcaws/ejbcaws?wsdl";
            log.info("Contacting webservice at " + urlstr);

            System.setProperty("javax.net.ssl.trustStore", "p12/wsnonadmintest.jks");
            System.setProperty("javax.net.ssl.trustStorePassword", "foo123");
            System.setProperty("javax.net.ssl.keyStore", "p12/wsnonadmintest.jks");
            System.setProperty("javax.net.ssl.keyStorePassword", "foo123");

            QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
            EjbcaWSService service = new EjbcaWSService(new URL(urlstr), qname);
            ejbcaraws = service.getEjbcaWSPort();

        }
    }

    public void test01checkNonAuthorizatied() throws Exception {
        setUpNonAdmin();

        // This is a superadmin keystore, improve in the future
        assertFalse(ejbcaraws.isAuthorized(AccessRulesConstants.ROLE_SUPERADMINISTRATOR));

        try {
            editUser();
            assertTrue(false);
        } catch (AuthorizationDeniedException_Exception e) {
        }

        try {
            findUser();
            assertTrue(false);
        } catch (AuthorizationDeniedException_Exception e) {
        }

        try {
            generatePkcs10();
            assertTrue(false);
        } catch (AuthorizationDeniedException_Exception e) {
        }

        try {
            generatePkcs12();
            assertTrue(false);
        } catch (AuthorizationDeniedException_Exception e) {
        }

        try {
            findCerts();
            assertTrue(false);
        } catch (AuthorizationDeniedException_Exception e) {
        }

        try {
            revokeCert();
            assertTrue(false);
        } catch (AuthorizationDeniedException_Exception e) {
        }

        try {
            revokeToken();
            assertTrue(false);
        } catch (AuthorizationDeniedException_Exception e) {
        }

        try {
            checkRevokeStatus();
            assertTrue(false);
        } catch (AuthorizationDeniedException_Exception e) {
        }

        try {
            utf8();
            assertTrue(false);
        } catch (AuthorizationDeniedException_Exception e) {
        }

        try {
            revokeUser();
            assertTrue(false);
        } catch (AuthorizationDeniedException_Exception e) {
        }

        try {
            getExistsHardToken();
            assertTrue(false);
        } catch (EjbcaException_Exception e) {
        }

        try {
            getHardTokenDatas();
            assertTrue(false);
        } catch (AuthorizationDeniedException_Exception e) {
        }

        try {
            customLog();
            assertTrue(false);
        } catch (AuthorizationDeniedException_Exception e) {
        }

        try {
            getCertificate();
            assertTrue(false);
        } catch (AuthorizationDeniedException_Exception e) {
        }
        try {
            checkQueueLength();
        } catch (AuthorizationDeniedException_Exception e) {
            assertTrue(false);
        }
    }

    public void test02GetHardTokenDataWithApprovals() throws Exception {

        final String serialNumber = "12344711";

        setUpNonAdmin();
        setupApprovals();

        ApprovalRequest approvalRequest = new ViewHardTokenDataApprovalRequest(TEST_NONADMIN_USERNAME, TEST_NONADMIN_CN, serialNumber, true, reqadmin, null, 1,
                0, 0);

        // Setup the test
        if (!hardTokenSessionRemote.existsHardToken(reqadmin, serialNumber)) {
            /*
             * Add an arbitrary token for the below two tests to wait for
             * (should such a token not already exist due to sloppy cleanup).
             */
            hardTokenSessionRemote.addHardToken(reqadmin, serialNumber, TEST_NONADMIN_USERNAME, TEST_NONADMIN_CN, SecConst.TOKEN_SWEDISHEID,
                    new SwedishEIDHardToken("1234", "12345678", "5678", "23456789", 1), new ArrayList<Certificate>(), null);

        }

        // Make sure that the ApprovalSession is clean.
        cleanApprovalRequestFromApprovalSession(approvalRequest, reqadmin);

        try {

            try {
                getHardTokenData(serialNumber, true);
                assertTrue(false);
            } catch (WaitingForApprovalException_Exception e) {
            }

            try {
                getHardTokenData(serialNumber, true);
                assertTrue(false);
            } catch (WaitingForApprovalException_Exception e) {
            }

            Approval approval1 = new Approval("ap1test");
            try {
                approvalExecutionSession.approve(admin1, approvalRequest.generateApprovalId(), approval1, gc);
                getHardTokenData(serialNumber, true);
                try {
                    getHardTokenData(serialNumber, true);
                    assertTrue(false);
                } catch (WaitingForApprovalException_Exception e) {
                }
                approvalSession.reject(admin1, approvalRequest.generateApprovalId(), approval1, gc);
                try {
                    getHardTokenData(serialNumber, true);
                    assertTrue(false);
                } catch (ApprovalRequestExecutionException_Exception e) {
                }
            } finally {
                // Clean up approval requests.
                cleanApprovalRequestFromApprovalSession(approvalRequest, reqadmin);
            }

        } finally {
            // Clean up hard token.
            hardTokenSessionRemote.removeHardToken(intadmin, serialNumber);

            removeApprovalAdmins();
        }
    }

    /**
     * Takes an ApprovalRequest and cleans all ApprovalRequests with the same
     * approval id from the ApprovalSession.
     * 
     * @param approvalRequest
     * @throws ApprovalException
     */
    private void cleanApprovalRequestFromApprovalSession(ApprovalRequest approvalRequest, Admin admin) throws ApprovalException {
        Collection<ApprovalDataVO> collection = approvalSession.findApprovalDataVO(reqadmin, approvalRequest.generateApprovalId());
        if (!collection.isEmpty()) {
            for (ApprovalDataVO approvalDataVO : collection) {
                approvalSession.removeApprovalRequest(admin, approvalDataVO.getId());
            }
        }
    }

    public void test03CleanGetHardTokenDataWithApprovals() throws Exception {
        setupApprovals();
        ApprovalRequest ar = new ViewHardTokenDataApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", "12345678", true, reqadmin, null, 1, 0, 0);

        Collection<ApprovalDataVO> result = approvalSession.findApprovalDataVO(intAdmin, ar.generateApprovalId());
        Iterator<ApprovalDataVO> iter = result.iterator();
        while (iter.hasNext()) {
            ApprovalDataVO next = iter.next();
            approvalSession.removeApprovalRequest(admin1, next.getId());
        }

        removeApprovalAdmins();
    }

    public void test04GenTokenCertificatesWithApprovals() throws Exception {
        setUpNonAdmin();
        setupApprovals();
        try {
            genTokenCertificates(true);
            assertTrue(false);
        } catch (WaitingForApprovalException_Exception e) {
        }

        try {
            genTokenCertificates(true);
            assertTrue(false);
        } catch (WaitingForApprovalException_Exception e) {
        }

        Approval approval1 = new Approval("ap1test");

        ApprovalRequest ar = new GenerateTokenApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", HardToken.LABEL_PROJECTCARD, reqadmin, null, 1, 0, 0);
        approvalExecutionSession.approve(admin1, ar.generateApprovalId(), approval1, gc);

        genTokenCertificates(true);

        try {
            getHardTokenData("12345678", true);
            assertTrue(false);
        } catch (WaitingForApprovalException_Exception e) {
        }

        try {
            genTokenCertificates(true);
            assertTrue(false);
        } catch (WaitingForApprovalException_Exception e) {
        }

        approvalSession.reject(admin1, ar.generateApprovalId(), approval1, gc);

        try {
            genTokenCertificates(true);
            assertTrue(false);
        } catch (ApprovalRequestExecutionException_Exception e) {
        }

        removeApprovalAdmins();
    }

    public void test05CleanGenTokenCertificatesWithApprovals() throws Exception {
        setupApprovals();
        ApprovalRequest ar = new GenerateTokenApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", HardToken.LABEL_PROJECTCARD, reqadmin, null, 1, 0, 0);

        Collection<ApprovalDataVO> result = approvalSession.findApprovalDataVO(intAdmin, ar.generateApprovalId());
        Iterator<ApprovalDataVO> iter = result.iterator();
        while (iter.hasNext()) {
            ApprovalDataVO next = iter.next();
            approvalSession.removeApprovalRequest(admin1, next.getId());
        }

        ar = new ViewHardTokenDataApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", "12345678", true, reqadmin, null, 1, 0, 0);

        result = approvalSession.findApprovalDataVO(intAdmin, ar.generateApprovalId());
        iter = result.iterator();
        while (iter.hasNext()) {
            ApprovalDataVO next = iter.next();
            approvalSession.removeApprovalRequest(admin1, next.getId());
        }

        removeApprovalAdmins();
        hardTokenSessionRemote.removeHardToken(intAdmin, "12345678");
        userAdminSession.revokeAndDeleteUser(intAdmin, "WSTESTTOKENUSER1", RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);

    }

    public void test99cleanUpAdmins() throws Exception {
        super.cleanUpAdmins();
    }

    //
    // private helper functions
    //
    private void setupApprovals() throws Exception {
        CryptoProviderTools.installBCProvider();

        adminusername1 = genRandomUserName();

        CAInfo cainfo = caAdminSessionRemote.getCAInfo(intAdmin, getAdminCAName());
        caid = cainfo.getCAId();

        UserDataVO userdata = new UserDataVO(adminusername1, "CN=" + adminusername1, caid, null, null, 1, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        userAdminSession.addUser(intadmin, userdata, true);

        BatchMakeP12 makep12 = new BatchMakeP12();
        File tmpfile = File.createTempFile("ejbca", "p12");

        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createAllNew();

        adminEntities = new ArrayList<AdminEntity>();
        adminEntities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME, AdminEntity.TYPE_EQUALCASEINS, adminusername1, caid));
        adminEntitySession.addAdminEntities(intadmin, AdminGroup.TEMPSUPERADMINGROUP, adminEntities);

        authorizationSession.forceRuleUpdate(intadmin);

        admincert1 = (X509Certificate) certificateStoreSession.findCertificatesByUsername(intadmin, adminusername1).iterator().next();

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream("p12/wsnonadmintest.jks"), "foo123".toCharArray());
        Enumeration<String> enumer = ks.aliases();
        X509Certificate reqadmincert = null;
        while (enumer.hasMoreElements()) {
            String nextAlias = enumer.nextElement();
            if (nextAlias.equals("wsnonadmintest")) {
                reqadmincert = (X509Certificate) ks.getCertificate(nextAlias);
            }
        }

        admin1 = new Admin(admincert1, adminusername1, null);
        reqadmin = userAdminSession.getAdmin(reqadmincert);
    }

    protected void removeApprovalAdmins() throws Exception {
        userAdminSession.deleteUser(intadmin, adminusername1);
        adminEntitySession.removeAdminEntities(intadmin, AdminGroup.TEMPSUPERADMINGROUP, adminEntities);

    }
}
