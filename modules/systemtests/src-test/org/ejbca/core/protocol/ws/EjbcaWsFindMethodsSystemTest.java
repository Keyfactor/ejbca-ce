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

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.cesecore.CaTestUtils;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

/**
 * Test class for working with the various find methods in EJBCA WS
 * 
 * @version $Id$
 *
 */
public class EjbcaWsFindMethodsSystemTest extends CommonEjbcaWsTest {

    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityProfileSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);

    private GlobalConfiguration originalGlobalConfiguration = null;
    private static List<File> fileHandles = new ArrayList<>();

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        adminBeforeClass();
        fileHandles = setupAccessRights(WS_ADMIN_ROLENAME);

    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        cleanUpAdmins(WS_ADMIN_ROLENAME);
        for (File file : fileHandles) {
            FileTools.delete(file);
        }
    }

    @Before
    public void setUpAdmin() throws Exception {
        adminSetUpAdmin();
        originalGlobalConfiguration = (GlobalConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        // Restore WS admin access
        setAccessRulesForWsAdmin(Arrays.asList(StandardRules.ROLE_ROOT.resource()), null);
        // Restore key recovery, end entity profile limitations etc
        if (originalGlobalConfiguration != null) {
            globalConfigurationSession.saveConfiguration(intAdmin, originalGlobalConfiguration);
        }
    }

    @Test
    public void testFindNonExistingUser() throws Exception {
        // Nonexisting users should return null
        final UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("noneExsisting");
        final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertNotNull(userdatas != null);
        assertEquals(0, userdatas.size());
    }

    @Test
    public void testFindExistingUser() throws Exception {
        final String endEntityProfileName = "testFindExistingUserEEP";
        final String certificateProfileName = "testFindExistingUserCP";
        int certificateProfileId = createCertificateProfile(certificateProfileName);
        createEndEndtityProfile(endEntityProfileName, certificateProfileId);
        final String username1 = "testFindUser1";
        final String caname = "FindUserTestCa";
        createTestCA(caname);
        createUser(username1, "CN="+username1, caname, endEntityProfileName, certificateProfileName);
        try {
            // Find an existing user
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(username1);
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertNotNull(userdatas);
            assertEquals("User with username " + username1 + " was not found", 1, userdatas.size());
        } finally {
            endEntityManagementSession.deleteUser(intAdmin, username1);
            internalCertificateStoreSession.removeCertificatesByUsername(username1);
            CaTestUtils.removeCa(intAdmin, caname, caname);
            endEntityProfileSession.removeEndEntityProfile(intAdmin, endEntityProfileName);
            certificateProfileSession.removeCertificateProfile(intAdmin, certificateProfileName);
        }

    }

    @Test
    public void testFindUserByOrganization() throws Exception {
        String prefix = "testFindUserByOrganization";
        final String endEntityProfileName = prefix + "EEP";
        final String certificateProfileName = prefix + "CP";
        int certificateProfileId = createCertificateProfile(certificateProfileName);
        createEndEndtityProfile(endEntityProfileName, certificateProfileId);
        final String username = prefix + "User1";
        final String caname = prefix + "TestCa";
        createTestCA(caname);
        final String organization = "FUBOrg";
        final String subjectDn = "CN="+username+",O="+organization;
        createUser(username, subjectDn, caname, endEntityProfileName, certificateProfileName);
        try {
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_ORGANIZATION);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_BEGINSWITH);
            usermatch.setMatchvalue(organization);
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertNotNull(userdatas);
            assertEquals("User with organization name (O) " + organization + " was not found.", 1, userdatas.size());
            assertEquals("Incorrect subject DN was returned.", subjectDn, userdatas.get(0).getSubjectDN());
        } finally {
            endEntityManagementSession.deleteUser(intAdmin, username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            CaTestUtils.removeCa(intAdmin, caname, caname);
            endEntityProfileSession.removeEndEntityProfile(intAdmin, endEntityProfileName);
            certificateProfileSession.removeCertificateProfile(intAdmin, certificateProfileName);
        }
    }
    
    @Test
    public void testFindUserBySubjectDn() throws Exception {
        String prefix = "testFindUserBySubjectDn";
        final String endEntityProfileName = prefix + "EEP";
        final String certificateProfileName = prefix + "CP";
        int certificateProfileId = createCertificateProfile(certificateProfileName);
        createEndEndtityProfile(endEntityProfileName, certificateProfileId);
        final String username = prefix + "User1";
        final String caname = prefix + "TestCa";
        createTestCA(caname);
        final String organization = "FUBOrg";
        final String subjectDn = "CN="+username+",O="+organization+",C=SE";
        createUser(username, subjectDn, caname, endEntityProfileName, certificateProfileName);
        try {
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_DN);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_CONTAINS);
            usermatch.setMatchvalue(username);
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertNotNull("No user was returned", userdatas);
            assertEquals("More than one user was returned", 1, userdatas.size());
            assertEquals("Wrong user was returned.", subjectDn, userdatas.get(0).getSubjectDN());
        } finally {
            endEntityManagementSession.deleteUser(intAdmin, username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            CaTestUtils.removeCa(intAdmin, caname, caname);
            endEntityProfileSession.removeEndEntityProfile(intAdmin, endEntityProfileName);
            certificateProfileSession.removeCertificateProfile(intAdmin, certificateProfileName);
        }
    }
    
    @Test
    public void testFindUserByEmail() throws Exception {
        String prefix = "testFindUserByEmail";
        final String endEntityProfileName = prefix + "EEP";
        final String certificateProfileName = prefix + "CP";
        int certificateProfileId = createCertificateProfile(certificateProfileName);
        createEndEndtityProfile(endEntityProfileName, certificateProfileId);
        final String username = prefix + "User1";
        final String caname = prefix + "TestCa";
        createTestCA(caname);
        final String subjectDn = "CN="+username+",C=SE";
        final String email = prefix+"@"+prefix+".com";
        createUser(username, subjectDn, email, caname, endEntityProfileName, certificateProfileName);
        try {
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_EMAIL);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(email);
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertNotNull("No users were returned.", userdatas);
            assertEquals("Incorrect number of users from e-mail match.", 1, userdatas.size());
            assertEquals("Wrong user was returned.", email, userdatas.get(0).getEmail());
        } finally {
            endEntityManagementSession.deleteUser(intAdmin, username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            CaTestUtils.removeCa(intAdmin, caname, caname);
            endEntityProfileSession.removeEndEntityProfile(intAdmin, endEntityProfileName);
            certificateProfileSession.removeCertificateProfile(intAdmin, certificateProfileName);
        }
    }
    
    @Test
    public void testFindUserByEndEntityProfile() throws Exception {
        String prefix = "testFindUserByEndEntityProfile";
        final String endEntityProfileName = prefix + "EEP";
        final String certificateProfileName = prefix + "CP";
        int certificateProfileId = createCertificateProfile(certificateProfileName);
        createEndEndtityProfile(endEntityProfileName, certificateProfileId);
        final String username = prefix + "User1";
        final String caname = prefix + "TestCa";
        createTestCA(caname);
        final String organization = "FUBOrg";
        final String subjectDn = "CN="+username+",O="+organization+",C=SE";
        createUser(username, subjectDn, caname, endEntityProfileName, certificateProfileName);
        try {
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_ENDENTITYPROFILE);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(endEntityProfileName);
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertNotNull("No users were returned.", userdatas);
            assertEquals("Incorrect number of users from end entity profile match.", 1, userdatas.size());
        } finally {
            endEntityManagementSession.deleteUser(intAdmin, username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            CaTestUtils.removeCa(intAdmin, caname, caname);
            endEntityProfileSession.removeEndEntityProfile(intAdmin, endEntityProfileName);
            certificateProfileSession.removeCertificateProfile(intAdmin, certificateProfileName);
        }
    }
    
    @Test
    public void testFindUserByCertificateProfile() throws Exception {
        String prefix = "testFindUserByCertificateProfile";
        final String endEntityProfileName = prefix + "EEP";
        final String certificateProfileName = prefix + "CP";
        int certificateProfileId = createCertificateProfile(certificateProfileName);
        createEndEndtityProfile(endEntityProfileName, certificateProfileId);
        final String username = prefix + "User1";
        final String caname = prefix + "TestCa";
        createTestCA(caname);
        final String organization = "FUBOrg";
        final String subjectDn = "CN="+username+",O="+organization+",C=SE";
        createUser(username, subjectDn, caname, endEntityProfileName, certificateProfileName);
        try {
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_CERTIFICATEPROFILE);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(certificateProfileName);
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertNotNull("No users were returned.",userdatas);
            assertEquals("Incorrect number of users from certificate profile match.", 1, userdatas.size());
        } finally {
            endEntityManagementSession.deleteUser(intAdmin, username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            CaTestUtils.removeCa(intAdmin, caname, caname);
            endEntityProfileSession.removeEndEntityProfile(intAdmin, endEntityProfileName);
            certificateProfileSession.removeCertificateProfile(intAdmin, certificateProfileName);
        }
    }
    
    @Test
    public void testFindUserByCa() throws Exception {
        String prefix = "testFindUserByCertificateProfile";
        final String endEntityProfileName = prefix + "EEP";
        final String certificateProfileName = prefix + "CP";
        int certificateProfileId = createCertificateProfile(certificateProfileName);
        createEndEndtityProfile(endEntityProfileName, certificateProfileId);
        final String username = prefix + "User1";
        final String caname = prefix + "TestCa";
        createTestCA(caname);
        final String organization = "FUBOrg";
        final String subjectDn = "CN="+username+",O="+organization+",C=SE";
        createUser(username, subjectDn, caname, endEntityProfileName, certificateProfileName);
        try {
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_CA);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(caname);
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertNotNull("No results were returned", userdatas);
            assertEquals("Incorrect number of users from CA match.", 1, userdatas.size());
        } finally {
            endEntityManagementSession.deleteUser(intAdmin, username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            CaTestUtils.removeCa(intAdmin, caname, caname);
            endEntityProfileSession.removeEndEntityProfile(intAdmin, endEntityProfileName);
            certificateProfileSession.removeCertificateProfile(intAdmin, certificateProfileName);
        }
    }
    
    @Test
    public void testFindUserByTokenType() throws Exception {
        String prefix = "testFindUserByCertificateProfile";
        final String endEntityProfileName = prefix + "EEP";
        final String certificateProfileName = prefix + "CP";
        int certificateProfileId = createCertificateProfile(certificateProfileName);
        createEndEndtityProfile(endEntityProfileName, certificateProfileId);
        final String username = prefix + "User1";
        final String caname = prefix + "TestCa";
        createTestCA(caname);
        final String organization = "FUBOrg";
        final String subjectDn = "CN="+username+",O="+organization+",C=SE";
        createUser(username, subjectDn, caname, endEntityProfileName, certificateProfileName);
        try {
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_TOKEN);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertNotNull("No results were returned", userdatas);
            assertTrue("No users with sought token type were found.", userdatas.size() > 0);
        } finally {
            endEntityManagementSession.deleteUser(intAdmin, username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            CaTestUtils.removeCa(intAdmin, caname, caname);
            endEntityProfileSession.removeEndEntityProfile(intAdmin, endEntityProfileName);
            certificateProfileSession.removeCertificateProfile(intAdmin, certificateProfileName);
        }
    }


    @Override
    public String getRoleName() {
        return "EjbcaWsFindMethodsTest";
    }

}
