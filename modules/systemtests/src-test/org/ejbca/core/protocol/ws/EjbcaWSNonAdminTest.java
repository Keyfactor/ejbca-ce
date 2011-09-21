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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
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
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessMatchValue;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.GenerateTokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ViewHardTokenDataApprovalRequest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.protocol.ws.client.gen.ApprovalRequestExecutionException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 
 * @version $Id$
 */
public class EjbcaWSNonAdminTest extends CommonEjbcaWS {

    private static final Logger log = Logger.getLogger(EjbcaWSNonAdminTest.class);

    private final String cliUserName = "ejbca";
    private final String cliPassword = "ejbca";
    
    private static String adminusername1 = null;
    private static X509Certificate admincert1 = null;
    private static AuthenticationToken admin1 = null;
    private static int caid;
    private static GlobalConfiguration gc = null;

    private List<AccessUserAspectData> adminEntities;
    private static final AuthenticationToken intadmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("WSTEST"));
    private AuthenticationToken reqadmin;

    private final AccessControlSessionRemote accessControlSession = InterfaceCache.getAccessControlSession();
    private final RoleAccessSessionRemote roleAccessSession = InterfaceCache.getRoleAccessSession();
    private final CaSessionRemote caSession = InterfaceCache.getCaSession();
    private final ApprovalExecutionSessionRemote approvalExecutionSession = InterfaceCache.getApprovalExecutionSession();
    private final ApprovalSessionRemote approvalSession = InterfaceCache.getApprovalSession();
    private final CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private final HardTokenSessionRemote hardTokenSessionRemote = InterfaceCache.getHardTokenSession();
    private final GlobalConfigurationSessionRemote globalConfigurationSession = InterfaceCache.getGlobalConfigurationSession();
    private final RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);

    private final String wsadminRoleName = "WsNonAdminTestRole";
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        System.setProperty("javax.net.ssl.trustStore", TEST_NONADMIN_FILE);
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWORD);
        System.setProperty("javax.net.ssl.keyStore", TEST_NONADMIN_FILE);
        System.setProperty("javax.net.ssl.keyStorePassword", PASSWORD);
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
            String urlstr = "https://" + hostname + ":" + httpsPort + "/ejbca/ejbcaws/ejbcaws?wsdl";
            log.info("Contacting webservice at " + urlstr);
            QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
            EjbcaWSService service = new EjbcaWSService(new URL(urlstr), qname);
            ejbcaraws = service.getEjbcaWSPort();
        }
    }

    @Test
    public void test00SetupAccessRights() throws Exception {        
        super.setupAccessRights(wsadminRoleName);
        gc = globalConfigurationSession.getCachedGlobalConfiguration(intadmin);
        assertNotNull("Unable to fetch GlobalConfiguration.");
    }

    @Test
    public void test01checkNonAuthorized() throws Exception {
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

    @Test
    public void test02GetHardTokenDataWithApprovals() throws Exception {

        final String serialNumber = "12344711";

        setUpNonAdmin();
        setupApprovals();

        ApprovalRequest approvalRequest = new ViewHardTokenDataApprovalRequest(TEST_NONADMIN_USERNAME, TEST_NONADMIN_CN, serialNumber, true, reqadmin, null, 1, 0, 0);

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
        ApprovalRequest ar = new ViewHardTokenDataApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", "12345678", true, reqadmin, null, 1, 0, 0);

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

    @Test
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

    @Test
    public void test99cleanUpAdmins() throws Exception {
        super.cleanUpAdmins(wsadminRoleName);
    }

    //
    // private helper functions
    //
    private void setupApprovals() throws Exception {

        adminusername1 = genRandomUserName();

        CAInfo cainfo = caSession.getCAInfo(intAdmin, getAdminCAName());
        caid = cainfo.getCAId();

        EndEntityInformation userData = new EndEntityInformation(adminusername1, "CN=" + adminusername1, caid, null, null, 1, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null); 
        userData.setPassword(PASSWORD);
        userAdminSession.addUser(intadmin, userData, true);

        BatchMakeP12 makep12 = new BatchMakeP12();
        File tmpfile = File.createTempFile("ejbca", "p12");

        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createAllNew(cliUserName, cliPassword);

        adminEntities = new ArrayList<AccessUserAspectData>();
        adminEntities.add(new AccessUserAspectData(getRoleName(), caid, AccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASEINS, adminusername1));  
        roleManagementSession.addSubjectsToRole(intadmin, roleAccessSession.findRole(getRoleName()), adminEntities);
        accessControlSession.forceCacheExpire();

        admincert1 = (X509Certificate) certificateStoreSession.findCertificatesByUsername(adminusername1).iterator().next();

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
        admin1 = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider.authenticate(new AuthenticationSubject(principals, null));

        Set<Principal> reqprincipals = new HashSet<Principal>();
        principals.add(reqadmincert.getSubjectX500Principal());
        reqadmin = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider.authenticate(new AuthenticationSubject(reqprincipals, null));
      
    }

    protected void removeApprovalAdmins() throws Exception {
        userAdminSession.deleteUser(intadmin, adminusername1);
        roleManagementSession.removeSubjectsFromRole(intadmin, roleAccessSession.findRole(getRoleName()), adminEntities);
    }
}
