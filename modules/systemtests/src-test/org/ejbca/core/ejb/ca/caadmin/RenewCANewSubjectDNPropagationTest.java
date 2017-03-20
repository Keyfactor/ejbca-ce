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

package org.ejbca.core.ejb.ca.caadmin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.Role;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests all kind of propagation (Rules, End Entity and Certificate profiles,...) 
 * occurred after the Name Change CA Renewal {@link CAAdminSession.renewCANewSubjectDn}
 * 
 * @version $Id: RenewCANewSubjectDNPropagationTest.java 22638 2016-01-22 21:55:34Z marko $
 */
public class RenewCANewSubjectDNPropagationTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(RenewCANewSubjectDNPropagationTest.class);
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RenewCATest"));
    private static boolean backupEnableIcaoCANameChangeValue = false;

    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static EndEntityProfileSessionRemote endEntityProfileSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityProfileSessionRemote.class);
    private static CertificateProfileSessionRemote certificateProfileSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class);
    private static RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private static RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private static RoleAccessSessionRemote roleAccessSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private static RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);

    private final static String newSubjectDN = "CN=NewName";
    private final static String newCAName = "NewName";
    private final static String testProfileName1 = "testEndEntityProfile1";
    private final static String testProfileName2 = "testEndEntityProfile2";
    private final static String testRole1 = "testRole1";
    private final static String testRole2 = "testRole2";
    private final static String testRole3 = "testRole3";

    private final static int DUMMY_CA_ID = 10;

    private AccessRuleData testAccessDataRule1Role1 = null;
    private AccessRuleData testAccessDataRule2Role1 = null;
    private AccessRuleData testAccessDataRule3Role1 = null;
    private AccessRuleData testAccessDataRule1Role2 = null;
    private AccessRuleData testAccessDataRule2Role2 = null;
    private AccessRuleData testAccessDataRule3Role2 = null;
    private AccessRuleData testAccessDataRule1Role3 = null;

    @BeforeClass
    public static void beforeClass() throws Exception {
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        backupEnableIcaoCANameChangeValue = globalConfiguration.getEnableIcaoCANameChange();
        globalConfiguration.setEnableIcaoCANameChange(true);
        globalConfigSession.saveConfiguration(internalAdmin, globalConfiguration);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        globalConfiguration.setEnableIcaoCANameChange(backupEnableIcaoCANameChangeValue);
        globalConfigSession.saveConfiguration(internalAdmin, globalConfiguration);
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        removeTestCA(newCAName);
        internalCertificateStoreSession.removeCRLs(internalAdmin, newSubjectDN); //Make sure CRLs data are deleted where issuerDN=new Subject DN!!!

        createTestEndEntityProfile(testProfileName1);
        createTestEndEntityProfile(testProfileName2);
        
        createTestCertificateProfile(testProfileName1);
        createTestCertificateProfile(testProfileName2);

        final CAInfo caInfo = caSession.getCAInfo(internalAdmin, "TEST");
        roleSession.persistRole(internalAdmin, new Role(null, testRole1, Arrays.asList(
                StandardRules.CAACCESS.resource() + caInfo.getCAId()
                ), null));
        roleSession.persistRole(internalAdmin, new Role(null, testRole2, Arrays.asList(
                StandardRules.CAACCESS.resource()
                ), Arrays.asList(
                        StandardRules.CAACCESS.resource() + caInfo.getCAId()
                        )));
        roleSession.persistRole(internalAdmin, new Role(null, testRole3, Arrays.asList(
                StandardRules.CAACCESS.resource() + DUMMY_CA_ID
                ), null));
        setUpLegacy(caInfo);
    }

    @Deprecated
    private void setUpLegacy(CAInfo caInfo) throws Exception {
        Collection<AccessRuleData> accessRules = new ArrayList<>();

        //Prepare some set of access rules that are going to be tested
        testAccessDataRule1Role1 = prepareTestAccessRuleData(testRole1, caInfo.getCAId(), AccessRuleState.RULE_ACCEPT, true);
        testAccessDataRule2Role1 = prepareTestAccessRuleData(testRole1, caInfo.getCAId(), AccessRuleState.RULE_DECLINE, false);
        testAccessDataRule3Role1 = prepareTestAccessRuleData(testRole1, caInfo.getCAId(), AccessRuleState.RULE_NOTUSED, false);
        accessRules.add(testAccessDataRule1Role1);
        accessRules.add(testAccessDataRule2Role1);
        accessRules.add(testAccessDataRule3Role1);
        roleManagementSession.addAccessRulesToRole(internalAdmin, roleManagementSession.create(internalAdmin, testRole1), accessRules);

        //Same rules add to test role 2
        testAccessDataRule1Role2 = prepareTestAccessRuleData(testRole2, caInfo.getCAId(), AccessRuleState.RULE_ACCEPT, true);
        testAccessDataRule2Role2 = prepareTestAccessRuleData(testRole2, caInfo.getCAId(), AccessRuleState.RULE_DECLINE, false);
        testAccessDataRule3Role2 = prepareTestAccessRuleData(testRole2, caInfo.getCAId(), AccessRuleState.RULE_NOTUSED, false);
        accessRules.clear();
        accessRules.add(testAccessDataRule1Role2);
        accessRules.add(testAccessDataRule2Role2);
        accessRules.add(testAccessDataRule3Role2);
        roleManagementSession.addAccessRulesToRole(internalAdmin, roleManagementSession.create(internalAdmin, testRole2), accessRules);

        //Test role 3 will have some random CAID=0 that will represent some CA not renewed
        testAccessDataRule1Role3 = prepareTestAccessRuleData(testRole3, DUMMY_CA_ID, AccessRuleState.RULE_ACCEPT, true);
        accessRules.clear();
        accessRules.add(testAccessDataRule1Role3);
        roleManagementSession.addAccessRulesToRole(internalAdmin, roleManagementSession.create(internalAdmin, testRole3), accessRules);
    }

    @After
    public void tearDown() throws Exception {
        for (final String roleName : Arrays.asList(testRole1,testRole2, testRole3)) {
            try {
                final Role role = roleSession.getRole(internalAdmin, null, roleName);
                if (role!=null) {
                    roleSession.deleteRoleIdempotent(internalAdmin, role.getRoleId());
                }
            } catch (Exception e) {
                log.debug(e.getMessage());
            }
        }
        tearDownlegacy();
        endEntityProfileSessionRemote.removeEndEntityProfile(internalAdmin, testProfileName1);
        endEntityProfileSessionRemote.removeEndEntityProfile(internalAdmin, testProfileName2);
        certificateProfileSessionRemote.removeCertificateProfile(internalAdmin, testProfileName1);
        certificateProfileSessionRemote.removeCertificateProfile(internalAdmin, testProfileName2);
        super.tearDown();
        removeTestCA(newCAName);
    }

    @Deprecated
    private void tearDownlegacy() throws Exception {
        roleManagementSession.remove(internalAdmin, roleAccessSessionRemote.findRole(testRole1));
        roleManagementSession.remove(internalAdmin, roleAccessSessionRemote.findRole(testRole2));
        roleManagementSession.remove(internalAdmin, roleAccessSessionRemote.findRole(testRole3));
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
    
    /** Creates access rule name for all rules used in this test */
    @Deprecated
    private String createAccessRuleName(int caid, AccessRuleState state, boolean recursion){
        return StandardRules.CAACCESS.resource() + caid + "/" + state.toString() + "/" + recursion;
    }

    /** SetUp method for creating all access rules going to be used in this test */
    @Deprecated
    AccessRuleData prepareTestAccessRuleData(String roleName, int caid, AccessRuleState state, boolean recursion) {
        return new AccessRuleData(roleName, createAccessRuleName(caid, state, recursion), state, recursion);
    }

    /** Creates access rule that should be expected for a accessRuleData clone */
    @Deprecated
    AccessRuleData prepareExpectedClone(AccessRuleData accessRuleData, int clonedCAID) {
        return new AccessRuleData("dummy", createAccessRuleName(clonedCAID, accessRuleData.getInternalState(), accessRuleData.getRecursive()), accessRuleData.getInternalState(), accessRuleData.getRecursive());
    }

    /** Make sure that test end entity profiles have "TEST" CA among available CAs */
    private void createTestEndEntityProfile(final String profileName) throws Exception {
        endEntityProfileSessionRemote.removeEndEntityProfile(internalAdmin, profileName);
        EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        Collection<String> availableCAIDsBeforeNameChange = new ArrayList<String>();
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        availableCAIDsBeforeNameChange.add(info.getCAId() + "");
        endEntityProfile.setAvailableCAsIDsAsStrings(availableCAIDsBeforeNameChange);
        endEntityProfileSessionRemote.addEndEntityProfile(internalAdmin, profileName, endEntityProfile);
    }
    
    /** Make sure that test certificate profiles have "TEST" CA among available CAs */
    private void createTestCertificateProfile(final String profileName) throws Exception {
        certificateProfileSessionRemote.removeCertificateProfile(internalAdmin, profileName);
        CertificateProfile certificateProfile = new CertificateProfile();
        List<Integer> availableCAIDsBeforeNameChange = new ArrayList<Integer>();
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        availableCAIDsBeforeNameChange.add(info.getCAId());
        certificateProfile.setAvailableCAs(availableCAIDsBeforeNameChange);
        certificateProfileSessionRemote.addCertificateProfile(internalAdmin, profileName, certificateProfile);
    }

    /** Helper method for getting access rule by its name */
    @Deprecated
    private AccessRuleData getAccessRuleDataSpecificToCAID(AdminGroupData adminGroupData, String accessRuleName) {
        for (AccessRuleData accessRuleData : adminGroupData.getAccessRules().values()) {
            if (accessRuleData.getAccessRuleName().equalsIgnoreCase(accessRuleName)) {
                return accessRuleData;
            }
        }
        return null;
    }

    @Test
    public void testPropagationAfterCARenewSubjectDN() throws Exception {
        log.trace(">testPropagationAfterCARenewSubjectDN()");

        CAInfo caInfoBeforeNameChange = caSession.getCAInfo(internalAdmin, "TEST");
        caAdminSession.renewCANewSubjectDn(internalAdmin, caInfoBeforeNameChange.getCAId(), /*regenerateKeys=*/true, /*customNotBefore=*/null,
                /*createLinkCertificates=*/false, newSubjectDN);
        CAInfo caInfoAfterNameChange = caSession.getCAInfo(internalAdmin, newCAName);
        
        //End entity profiles propagation has to add new caid to availableCAs field
        Map<Integer, String> endEntityProfileIdToNameMap = endEntityProfileSessionRemote.getEndEntityProfileIdToNameMap();
        for (Integer profileIds : endEntityProfileIdToNameMap.keySet()) {
            EndEntityProfile endEntityProfile = endEntityProfileSessionRemote.getEndEntityProfile(profileIds);
            int cAHitCounter = 0;
            for (String availableCAIdAsString : endEntityProfile.getAvailableCAs()) {
                if (availableCAIdAsString.equalsIgnoreCase(caInfoBeforeNameChange.getCAId() + "") ||
                        availableCAIdAsString.equalsIgnoreCase(caInfoAfterNameChange.getCAId() + "")) {
                    cAHitCounter++;
                }
            }
            assertTrue("End entity profiles availableCAs field doesn't seem to propagade after the CA Name Change renewal",
                    cAHitCounter == 2 || cAHitCounter == 0);
        }
        
        //Certificate profiles propagation has to add new caid to availableCAs field
        Map<Integer, String> certificateProfileIdToNameMap = certificateProfileSessionRemote.getCertificateProfileIdToNameMap();
        for (Integer profileIds : certificateProfileIdToNameMap.keySet()) {
            CertificateProfile certificateProfile = certificateProfileSessionRemote.getCertificateProfile(profileIds);
            int cAHitCounter = 0;
            for (Integer availableCAId : certificateProfile.getAvailableCAs()) {
                if (availableCAId == caInfoBeforeNameChange.getCAId() ||
                        availableCAId == caInfoAfterNameChange.getCAId()) {
                    cAHitCounter++;
                }
            }
            assertTrue("Certificate profiles availableCAs field doesn't seem to propagade after the CA Name Change renewal",
                    cAHitCounter == 2 || cAHitCounter == 0);
        }
        
        //Access Rules propagation has to clone any rules that had contained caid before the Name Change CA Renewal
        //e.g. /ca/12345/ has to be cloned to /ca/6789/ where "12345" and "6789" are CA IDs before and after the renewal
        // TODO: Nuke the below related to old authorization system and uncomment the assertEquals in the end
        AdminGroupData testRoleData1 = roleAccessSessionRemote.findRole(testRole1);
        AccessRuleData expectedAccessDataRule1Role1 = prepareExpectedClone(testAccessDataRule1Role1, caInfoAfterNameChange.getCAId());
        AccessRuleData foundAccessDataRule1Role1 = getAccessRuleDataSpecificToCAID(testRoleData1, expectedAccessDataRule1Role1.getAccessRuleName());
        assertEqualAccessRuleData(expectedAccessDataRule1Role1, foundAccessDataRule1Role1);
        
        AccessRuleData expectedAccessDataRule2Role1 = prepareExpectedClone(testAccessDataRule2Role1, caInfoAfterNameChange.getCAId());
        AccessRuleData foundAccessDataRule2Role1 = getAccessRuleDataSpecificToCAID(testRoleData1, expectedAccessDataRule2Role1.getAccessRuleName());
        assertEqualAccessRuleData(expectedAccessDataRule2Role1, foundAccessDataRule2Role1);
        
        AccessRuleData expectedAccessDataRule3Role1 = prepareExpectedClone(testAccessDataRule3Role1, caInfoAfterNameChange.getCAId());
        AccessRuleData foundAccessDataRule3Role1 = getAccessRuleDataSpecificToCAID(testRoleData1, expectedAccessDataRule3Role1.getAccessRuleName());
        assertEqualAccessRuleData(expectedAccessDataRule3Role1, foundAccessDataRule3Role1);
        
        AdminGroupData testRoleData2 = roleAccessSessionRemote.findRole(testRole2);
        AccessRuleData expectedAccessDataRule1Role2 = prepareExpectedClone(testAccessDataRule1Role2, caInfoAfterNameChange.getCAId());
        AccessRuleData foundAccessDataRule1Role2 = getAccessRuleDataSpecificToCAID(testRoleData2, expectedAccessDataRule1Role2.getAccessRuleName());
        assertEqualAccessRuleData(expectedAccessDataRule1Role2, foundAccessDataRule1Role2);
        
        AccessRuleData expectedAccessDataRule2Role2 = prepareExpectedClone(testAccessDataRule2Role2, caInfoAfterNameChange.getCAId());
        AccessRuleData foundAccessDataRule2Role2 = getAccessRuleDataSpecificToCAID(testRoleData2, expectedAccessDataRule2Role2.getAccessRuleName());
        assertEqualAccessRuleData(expectedAccessDataRule2Role2, foundAccessDataRule2Role2);
        
        AccessRuleData expectedAccessDataRule3Role2 = prepareExpectedClone(testAccessDataRule3Role2, caInfoAfterNameChange.getCAId());
        AccessRuleData foundAccessDataRule3Role2 = getAccessRuleDataSpecificToCAID(testRoleData2, expectedAccessDataRule3Role2.getAccessRuleName());
        assertEqualAccessRuleData(expectedAccessDataRule3Role2, foundAccessDataRule3Role2);
        
        AdminGroupData testRoleData3 = roleAccessSessionRemote.findRole(testRole3);
        AccessRuleData expectedAccessDataRule1Role3 = prepareExpectedClone(testAccessDataRule1Role3, caInfoAfterNameChange.getCAId());
        AccessRuleData foundAccessDataRule1Role3 = getAccessRuleDataSpecificToCAID(testRoleData3, expectedAccessDataRule1Role3.getAccessRuleName());
        assertNull(expectedAccessDataRule1Role3 + " has been cloned during Name Change CA Renewal although this CA is not renewed. ", foundAccessDataRule1Role3);

        final int caIdOld = caInfoBeforeNameChange.getCAId();
        final int caIdNew = caInfoAfterNameChange.getCAId();
        final Map<String,Boolean> accessRulesForRole1 = roleSession.getRole(internalAdmin, null, testRole1).getAccessRules();
        assertEquals(Role.STATE_ALLOW, accessRulesForRole1.get(StandardRules.CAACCESS.resource() + caIdOld + "/"));
        assertEquals(Role.STATE_ALLOW, accessRulesForRole1.get(StandardRules.CAACCESS.resource() + caIdNew + "/"));
        final Map<String,Boolean> accessRulesForRole2 = roleSession.getRole(internalAdmin, null, testRole2).getAccessRules();
        assertEquals(Role.STATE_ALLOW, accessRulesForRole2.get(StandardRules.CAACCESS.resource()));
        assertEquals(Role.STATE_DENY, accessRulesForRole2.get(StandardRules.CAACCESS.resource() + caIdOld + "/"));
        assertEquals(Role.STATE_DENY, accessRulesForRole2.get(StandardRules.CAACCESS.resource() + caIdNew + "/"));
        final Map<String,Boolean> accessRulesForRole3 = roleSession.getRole(internalAdmin, null, testRole3).getAccessRules();
        assertEquals(1, accessRulesForRole3.size());
        assertEquals(Role.STATE_ALLOW, accessRulesForRole3.get(StandardRules.CAACCESS.resource() + DUMMY_CA_ID + "/"));
        log.trace("<testPropagationAfterCARenewSubjectDN()");
    }
    
    @Deprecated
    private void assertEqualAccessRuleData(AccessRuleData expectedAccessRule, AccessRuleData foundAccessRule){
        assertTrue(expectedAccessRule.getAccessRuleName() + " could not be found (it should've been created during the Name Change CA Renewal). ", foundAccessRule != null);
        assertTrue(foundAccessRule.getAccessRuleName() + ".getRecursive field is not copied during the Name Change CA Renewal.", expectedAccessRule.getRecursive() == foundAccessRule.getRecursive());
        assertTrue(foundAccessRule.getAccessRuleName() + ".getInternalState() field is not copied during the Name Change CA Renewal.", expectedAccessRule.getInternalState() == foundAccessRule.getInternalState());
    }

}
