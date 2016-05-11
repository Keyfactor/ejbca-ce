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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalProfile;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.GenerateTokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ViewHardTokenDataApprovalRequest;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.protocol.ws.client.gen.ApprovalRequestExecutionException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EjbcaWSNonAdminTest extends CommonEjbcaWS {

    private static final Logger log = Logger.getLogger(EjbcaWSNonAdminTest.class);

    private static final String WS_ADMIN_ROLENAME = "WsNonAdminTestRole";
    
    private static String adminusername1 = null;
    private static X509Certificate admincert1 = null;
    private static AuthenticationToken admin1 = null;
    private static int caid;

    private List<AccessUserAspectData> adminEntities;
    private static final AuthenticationToken intadmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWSNonAdminTest"));
    private AuthenticationToken reqadmin;

    private final AccessControlSessionRemote accessControlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
    private final ApprovalExecutionSessionRemote approvalExecutionSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalExecutionSessionRemote.class);
    private final ApprovalSessionRemote approvalSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final HardTokenSessionRemote hardTokenSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(HardTokenSessionRemote.class);
    private final RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private final RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private final SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private static List<File> fileHandles = new ArrayList<File>();
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        setAdminCAName();
        fileHandles =  setupAccessRights(WS_ADMIN_ROLENAME);
        assertNotNull("Unable to fetch GlobalConfiguration.");
    }

    @AfterClass
    public static void afterClass() {
        for (File file : fileHandles) {
            FileTools.delete(file);
        }
    }
    
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }
    
    public String getRoleName() {
        return "EjbcaWSTestNonAdmin";
    }

    private void setUpNonAdmin() throws Exception {
        if (new File(TEST_NONADMIN_FILE).exists()) {
            
            System.setProperty("javax.net.ssl.trustStore", TEST_NONADMIN_FILE);
            System.setProperty("javax.net.ssl.trustStorePassword", PASSWORD);
            System.setProperty("javax.net.ssl.keyStore", TEST_NONADMIN_FILE);
            System.setProperty("javax.net.ssl.keyStorePassword", PASSWORD);

            createEjbcaWSPort("https://" + hostname + ":" + httpsPort + "/ejbca/ejbcaws/ejbcaws?wsdl");
        } else {
            log.error("No file '"+TEST_NONADMIN_FILE+"' exists.");
        }
    }
    
    private void createEjbcaWSPort(final String url) throws MalformedURLException {
        log.info("Contacting webservice at " + url);
        QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
        EjbcaWSService service = new EjbcaWSService(new URL(url), qname);
        this.ejbcaraws = service.getEjbcaWSPort();        
    }

    @Test
    public void test01checkNonAuthorized() throws Exception {
        setUpNonAdmin();

        // This is a superadmin keystore, improve in the future
        assertFalse(ejbcaraws.isAuthorized(StandardRules.ROLE_ROOT.resource()));

        try {
            editUser();
            fail("should not have been allowed to create users");
        } catch (AuthorizationDeniedException_Exception e) {
            // NOPMD: this is what we want
        }

        try {
            findUser();
            fail("should not have been allowed to find users");
        } catch (AuthorizationDeniedException_Exception e) {
            // NOPMD: this is what we want
        }

        try {
            generatePkcs10();
            fail("should not have been allowed to generate pkcs10");
        } catch (AuthorizationDeniedException_Exception e) {
            // NOPMD: this is what we want
        }

        try {
            generatePkcs12();
            fail("should not have been allowed to generate pkcs12");
        } catch (AuthorizationDeniedException_Exception e) {
            // NOPMD: this is what we want
        }

        try {
            findCerts();
            fail("should not have been allowed to find certs");
        } catch (AuthorizationDeniedException_Exception e) {
            // NOPMD: this is what we want
        }

        try {
            revokeCert();
            fail("should not have been allowed to revoke cert");
        } catch (AuthorizationDeniedException_Exception e) {
            // NOPMD: this is what we want
        }

        try {
            revokeCertBackdated();
            fail("should not have been allowed to revoke cert");
        } catch (AuthorizationDeniedException_Exception e) {
            // NOPMD: this is what we want
        }

        try {
            revokeToken();
            fail("should not have been allowed to revoke token");
        } catch (AuthorizationDeniedException_Exception e) {
            // NOPMD: this is what we want
        }

        try {
            checkRevokeStatus();
            fail("should not have been allowed to check revoke status");
        } catch (AuthorizationDeniedException_Exception e) {
            // NOPMD: this is what we want
        }

        try {
            utf8EditUser();
            fail("should not have been allowed to edit utf8 user");
        } catch (AuthorizationDeniedException_Exception e) {
            // NOPMD: this is what we want
        }

        try {
            revokeUser();
            fail("should not have been allowed to revoke user");
        } catch (AuthorizationDeniedException_Exception e) {
            // NOPMD: this is what we want
        }

        try {
            getExistsHardToken();
            fail("should not have been allowed to check hard tokens");
        } catch (EjbcaException_Exception e) {
            // NOPMD: this is what we want
        }

        try {
            getHardTokenDatas();
            fail("should not have been allowed to get hard token");
        } catch (AuthorizationDeniedException_Exception e) {
        }

        try {
            customLog();
            fail("should not have been allowed to custom log");
        } catch (AuthorizationDeniedException_Exception e) {
            // NOPMD: this is what we want
        }

        try {
            getCertificate();
            fail("should not have been allowed to get certificate");
        } catch (AuthorizationDeniedException_Exception e) {
            // NOPMD: this is what we want
        }
        try {
            checkQueueLength();
        } catch (AuthorizationDeniedException_Exception e) {
            fail("should have been allowed to check queue length");
        }
    }

    @Test
    public void test02GetHardTokenDataWithApprovals() throws Exception {

        final String serialNumber = "12344711";

        setUpNonAdmin();
        setupApprovals();

        ApprovalProfile approvalProfile = new ApprovalProfile();
        approvalProfile.setNumberOfApprovals(1);
        ApprovalRequest approvalRequest = new ViewHardTokenDataApprovalRequest(TEST_NONADMIN_USERNAME, TEST_NONADMIN_CN, 
                serialNumber, true, reqadmin, null, 1, 0, 0, approvalProfile, null);

        // Setup the test
        if (!hardTokenSessionRemote.existsHardToken(serialNumber)) {
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
                fail("should be waiting for approval");
            } catch (WaitingForApprovalException_Exception e) {
                // NOPMD: desired
            }

            try {
                getHardTokenData(serialNumber, true);
                fail("should be waiting for approval");
            } catch (WaitingForApprovalException_Exception e) {
                // NOPMD: desired
            }

            Approval approval1 = new Approval("ap1test");
            try {
                log.debug("ID: "+approvalRequest.generateApprovalId());
                approvalExecutionSession.approve(admin1, approvalRequest.generateApprovalId(), approval1, null, true);
                getHardTokenData(serialNumber, true);
                try {
                    getHardTokenData(serialNumber, true);
                    fail("should be waiting for approval");
                } catch (WaitingForApprovalException_Exception e) {
                    // NOPMD: desired
                }
                approvalSession.reject(admin1, approvalRequest.generateApprovalId(), approval1, null, true);
                try {
                    getHardTokenData(serialNumber, true);
                    fail("should not work");
                } catch (ApprovalRequestExecutionException_Exception e) {
                    // NOPMD: desired
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
    private void cleanApprovalRequestFromApprovalSession(ApprovalRequest approvalRequest, AuthenticationToken admin) throws ApprovalException {
        Collection<ApprovalDataVO> collection = approvalSession.findApprovalDataVO(reqadmin, approvalRequest.generateApprovalId());
        if (!collection.isEmpty()) {
            for (ApprovalDataVO approvalDataVO : collection) {
                approvalSession.removeApprovalRequest(admin, approvalDataVO.getId());
            }
        }
    }

    @Test
    public void test03CleanGetHardTokenDataWithApprovals() throws Exception {
        setupApprovals();
        ApprovalProfile approvalProfile = new ApprovalProfile();
        approvalProfile.setNumberOfApprovals(1);
        ApprovalRequest ar = new ViewHardTokenDataApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", "12345678", 
                true, reqadmin, null, 1, 0, 0, approvalProfile, null);

        Collection<ApprovalDataVO> result = approvalSession.findApprovalDataVO(intAdmin, ar.generateApprovalId());
        Iterator<ApprovalDataVO> iter = result.iterator();
        while (iter.hasNext()) {
            ApprovalDataVO next = iter.next();
            approvalSession.removeApprovalRequest(admin1, next.getId());
        }

        removeApprovalAdmins();
    }

    @Test
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

        ApprovalProfile approvalProfile = new ApprovalProfile();
        approvalProfile.setNumberOfApprovals(1);
        ApprovalRequest ar = new GenerateTokenApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", HardToken.LABEL_PROJECTCARD, 
                reqadmin, null, 1, 0, 0, approvalProfile, null);
        approvalExecutionSession.approve(admin1, ar.generateApprovalId(), approval1, null, true);

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

        approvalSession.reject(admin1, ar.generateApprovalId(), approval1, null, true);

        try {
            genTokenCertificates(true);
            assertTrue(false);
        } catch (ApprovalRequestExecutionException_Exception e) {
        }

        removeApprovalAdmins();
    }

    @Test
    public void test05CleanGenTokenCertificatesWithApprovals() throws Exception {
        setupApprovals();
        ApprovalProfile approvalProfile = new ApprovalProfile();
        approvalProfile.setNumberOfApprovals(1);
        ApprovalRequest ar = new GenerateTokenApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", HardToken.LABEL_PROJECTCARD, 
                reqadmin, null, 1, 0, 0, approvalProfile, null);

        Collection<ApprovalDataVO> result = approvalSession.findApprovalDataVO(intAdmin, ar.generateApprovalId());
        Iterator<ApprovalDataVO> iter = result.iterator();
        while (iter.hasNext()) {
            ApprovalDataVO next = iter.next();
            approvalSession.removeApprovalRequest(admin1, next.getId());
        }

        ar = new ViewHardTokenDataApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", "12345678", true, reqadmin, null, 1, 0, 
                0, approvalProfile, null);

        result = approvalSession.findApprovalDataVO(intAdmin, ar.generateApprovalId());
        iter = result.iterator();
        while (iter.hasNext()) {
            ApprovalDataVO next = iter.next();
            approvalSession.removeApprovalRequest(admin1, next.getId());
        }

        removeApprovalAdmins();
        hardTokenSessionRemote.removeHardToken(intAdmin, "12345678");
        endEntityManagementSession.revokeAndDeleteUser(intAdmin, "WSTESTTOKENUSER1", RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);

    }

    @AfterClass
    public static void cleanUpAdmins() throws Exception {
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        cleanUpAdmins(WS_ADMIN_ROLENAME);
        if (endEntityManagementSession.existsUser("WSTESTTOKENUSER1")) {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, "WSTESTTOKENUSER1", RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        }

    }

    //
    // private helper functions
    //
    private void setupApprovals() throws Exception {

        adminusername1 = genRandomUserName();

        CAInfo cainfo = caSession.getCAInfo(intAdmin, getAdminCAName());
        caid = cainfo.getCAId();

        EndEntityInformation userData = new EndEntityInformation(adminusername1, "CN=" + adminusername1, caid, null, null, new EndEntityType(EndEntityTypes.ENDUSER),
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        userData.setPassword(PASSWORD);
        endEntityManagementSession.addUser(intadmin, userData, true);

        fileHandles.addAll(BatchCreateTool.createAllNew(intadmin, new File(P12_FOLDER_NAME)));
        adminEntities = new ArrayList<AccessUserAspectData>();
        adminEntities.add(new AccessUserAspectData(getRoleName(), caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASEINS, adminusername1));  
        roleManagementSession.addSubjectsToRole(intadmin, roleAccessSession.findRole(getRoleName()), adminEntities);
        accessControlSession.forceCacheExpire();

        admincert1 = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(adminusername1)).iterator().next();

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(TEST_NONADMIN_FILE), PASSWORD.toCharArray());
        Enumeration<String> enumer = ks.aliases();
        X509Certificate reqadmincert = null;
        while (enumer.hasMoreElements()) {
            String nextAlias = enumer.nextElement();
            if (nextAlias.equals(TEST_NONADMIN_USERNAME)) {
                reqadmincert = (X509Certificate) ks.getCertificate(nextAlias);
            }
        }

        Set<Principal> principals = new HashSet<Principal>();
        principals.add(admincert1.getSubjectX500Principal());
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(admincert1);
        admin1 = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider.authenticate(new AuthenticationSubject(principals, credentials));

        Set<Principal> reqprincipals = new HashSet<Principal>();
        principals.add(reqadmincert.getSubjectX500Principal());
        Set<X509Certificate> reqcredentials = new HashSet<X509Certificate>();
        reqcredentials.add(reqadmincert);
        reqadmin = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider.authenticate(new AuthenticationSubject(reqprincipals, reqcredentials));
      
    }

    protected void removeApprovalAdmins() throws Exception {
        endEntityManagementSession.deleteUser(intadmin, adminusername1);
        roleManagementSession.removeSubjectsFromRole(intadmin, roleAccessSession.findRole(getRoleName()), adminEntities);
    }
}
