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
package org.ejbca.core.ejb.upgrade;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension;
import org.cesecore.certificates.certificate.certextensions.CertificateExtentionConfigurationException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.upgrade.UpgradeSessionRemote;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * System tests for the upgrade session bean. 
 * 
 * @version $Id$
 *
 */
public class UpgradeSessionBeanTest {

    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private UpgradeSessionRemote upgradeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(UpgradeSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private CertificateProfileSessionRemote certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);

    private AuthenticationToken alwaysAllowtoken = new TestAlwaysAllowLocalAuthenticationToken("UpgradeSessionBeanTest");
    
    private AvailableCustomCertificateExtensionsConfiguration cceConfigBackup;
    
    @Before
    public void setUp() {
        cceConfigBackup = (AvailableCustomCertificateExtensionsConfiguration) globalConfigSession.
                getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
    }
    
    @After
    public void tearDown() throws Exception {
        globalConfigSession.saveConfiguration(alwaysAllowtoken, cceConfigBackup);
    }

    /**
     * This test will perform the upgrade step to 6.4.0, which is update of access rules, adding read-only rules to any roles which previously had them.
     * 
     */
    @Test
    public void testPostUpgradeTo640() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
        //Create a role specifically to test that read only access is given. 
        final String readOnlyRoleName = "ReadOnlyRole"; 
        RoleData readOnlyRole = roleManagementSession.create(alwaysAllowtoken, readOnlyRoleName);
        List<AccessRuleData> oldAccessRules = new ArrayList<AccessRuleData>();
        oldAccessRules.add(new AccessRuleData(readOnlyRole.getRoleName(), AccessRulesConstants.REGULAR_ACTIVATECA, AccessRuleState.RULE_ACCEPT, false));
        oldAccessRules.add(new AccessRuleData(readOnlyRole.getRoleName(), StandardRules.CAFUNCTIONALITY.resource(), AccessRuleState.RULE_ACCEPT, true));
        oldAccessRules.add(new AccessRuleData(readOnlyRole.getRoleName(), StandardRules.CERTIFICATEPROFILEEDIT.resource(), AccessRuleState.RULE_ACCEPT, false));
        oldAccessRules.add(new AccessRuleData(readOnlyRole.getRoleName(), AccessRulesConstants.REGULAR_EDITPUBLISHER, AccessRuleState.RULE_ACCEPT, false));
        oldAccessRules.add(new AccessRuleData(readOnlyRole.getRoleName(), AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES, AccessRuleState.RULE_ACCEPT, false));
        oldAccessRules.add(new AccessRuleData(readOnlyRole.getRoleName(), StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, false));
        oldAccessRules.add(new AccessRuleData(readOnlyRole.getRoleName(), InternalKeyBindingRules.BASE.resource(), AccessRuleState.RULE_ACCEPT, false));
        readOnlyRole = roleManagementSession.addAccessRulesToRole(alwaysAllowtoken, readOnlyRole, oldAccessRules);
        roleManagementSession.addSubjectsToRole(alwaysAllowtoken, readOnlyRole, Arrays.asList(new AccessUserAspectData(readOnlyRoleName, 1,
                X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASEINS, "CN=foo")));
        try {
            upgradeSession.upgrade(null, "6.3.2", true);
            RoleData upgradedRole = roleAccessSession.findRole(readOnlyRoleName);
            assertTrue(
                    "Role was not upgraded with rule " + StandardRules.CAVIEW.resource(),
                    upgradedRole.getAccessRules().containsValue(
                            new AccessRuleData(readOnlyRoleName, StandardRules.CAVIEW.resource(), AccessRuleState.RULE_ACCEPT, false)));
            assertTrue(
                    "Role was not upgraded with rule " + StandardRules.CERTIFICATEPROFILEVIEW.resource(),
                    upgradedRole.getAccessRules()
                            .containsValue(
                                    new AccessRuleData(readOnlyRoleName, StandardRules.CERTIFICATEPROFILEVIEW.resource(),
                                            AccessRuleState.RULE_ACCEPT, false)));
            assertTrue(
                    "Role was not upgraded with rule " + AccessRulesConstants.REGULAR_VIEWPUBLISHER,
                    upgradedRole.getAccessRules().containsValue(
                            new AccessRuleData(readOnlyRoleName, AccessRulesConstants.REGULAR_VIEWPUBLISHER, AccessRuleState.RULE_ACCEPT, false)));
            assertTrue(
                    "Role was not upgraded with rule " + AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES,
                    upgradedRole.getAccessRules().containsValue(
                            new AccessRuleData(readOnlyRoleName, AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES, AccessRuleState.RULE_ACCEPT,
                                    false)));
            assertTrue(
                    "Role was not upgraded with rule " + AccessRulesConstants.SERVICES_EDIT,
                    upgradedRole.getAccessRules().containsValue(
                            new AccessRuleData(readOnlyRoleName, AccessRulesConstants.SERVICES_EDIT, AccessRuleState.RULE_ACCEPT, false)));
            assertTrue(
                    "Role was not upgraded with rule " + AccessRulesConstants.SERVICES_VIEW,
                    upgradedRole.getAccessRules().containsValue(
                            new AccessRuleData(readOnlyRoleName, AccessRulesConstants.SERVICES_VIEW, AccessRuleState.RULE_ACCEPT, false)));
            assertTrue(
                    "Role was not upgraded with rule " + AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW,
                    upgradedRole.getAccessRules().containsValue(
                            new AccessRuleData(readOnlyRoleName, AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW, AccessRuleState.RULE_ACCEPT, true)));
            assertTrue(
                    "Role was not upgraded with rule " + InternalKeyBindingRules.VIEW.resource(),
                    upgradedRole.getAccessRules().containsValue(
                            new AccessRuleData(readOnlyRoleName, InternalKeyBindingRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true)));

        } finally {
            roleManagementSession.remove(alwaysAllowtoken, readOnlyRoleName);
        }
    }
    
   /**
    * This test will perform the upgrade step to 6.4.0 and tests update of access rules. Rules specific to editing available extended key usages and 
    * custom certificate extensions should be added to any role that is already allowed to edit system configurations, but not other roles.
    */
   @Test
   public void testPostUpgradeTo640EKUAndCustomCertExtensionsAccessRules() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
       
       // Add a role whose access rules should change after upgrade
       final String sysConfigRoleName = "SystemConfigRole"; 
       RoleData sysConfigRole  = roleManagementSession.create(alwaysAllowtoken, sysConfigRoleName);
       List<AccessRuleData> oldSysConfigAccessRules = new ArrayList<AccessRuleData>();
       oldSysConfigAccessRules.add(new AccessRuleData(sysConfigRole.getRoleName(), StandardRules.REGULAR_EDITSYSTEMCONFIGURATION.resource(), AccessRuleState.RULE_ACCEPT, false));
       sysConfigRole = roleManagementSession.addAccessRulesToRole(alwaysAllowtoken, sysConfigRole, oldSysConfigAccessRules);
       
       // Add a role whose access rules should NOT change after upgrade
       final String caAdmRoleName = "CaAdminRole"; 
       RoleData caAdmRole  = roleManagementSession.create(alwaysAllowtoken, caAdmRoleName);
       List<AccessRuleData> oldCaAdmAccessRules = new ArrayList<AccessRuleData>();
       oldCaAdmAccessRules.add(new AccessRuleData(caAdmRole.getRoleName(), StandardRules.CAFUNCTIONALITY.resource(), AccessRuleState.RULE_ACCEPT, true));
       oldCaAdmAccessRules.add(new AccessRuleData(caAdmRole.getRoleName(), StandardRules.CERTIFICATEPROFILEEDIT.resource(), AccessRuleState.RULE_ACCEPT, false));
       oldCaAdmAccessRules.add(new AccessRuleData(caAdmRole.getRoleName(), AccessRulesConstants.REGULAR_EDITPUBLISHER, AccessRuleState.RULE_ACCEPT, false));
       oldCaAdmAccessRules.add(new AccessRuleData(caAdmRole.getRoleName(), AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES, AccessRuleState.RULE_ACCEPT, false));
       caAdmRole = roleManagementSession.addAccessRulesToRole(alwaysAllowtoken, caAdmRole, oldCaAdmAccessRules);
       
       try {
           upgradeSession.upgrade(null, "6.3.2", true);
           
           // Verify that sysConfigRole's access rules contained rules to edit available extended key usages and custom certificate extensions
           RoleData upgradedSysConfigRole = roleAccessSession.findRole(sysConfigRoleName);
           assertEquals(3, upgradedSysConfigRole.getAccessRules().size());
           assertTrue(
                   "Role was not upgraded with rule " + StandardRules.REGULAR_EDITSYSTEMCONFIGURATION.resource(),
                   upgradedSysConfigRole.getAccessRules().containsValue(
                           new AccessRuleData(sysConfigRoleName, StandardRules.REGULAR_EDITSYSTEMCONFIGURATION.resource(), AccessRuleState.RULE_ACCEPT, false)));
           assertTrue(
                   "Role was not upgraded with rule " + StandardRules.REGULAR_EDITAVAILABLEEKU.resource(),
                   upgradedSysConfigRole.getAccessRules()
                           .containsValue(
                                   new AccessRuleData(sysConfigRoleName, StandardRules.REGULAR_EDITAVAILABLEEKU.resource(),
                                           AccessRuleState.RULE_ACCEPT, false)));
           
           assertTrue(
                   "Role was not upgraded with rule " + StandardRules.REGULAR_EDITAVAILABLECUSTOMCERTEXTENSION.resource(),
                   upgradedSysConfigRole.getAccessRules()
                           .containsValue(
                                   new AccessRuleData(sysConfigRoleName, StandardRules.REGULAR_EDITAVAILABLECUSTOMCERTEXTENSION.resource(),
                                           AccessRuleState.RULE_ACCEPT, false)));
           
           
           
           // Verify that caAdmRole's access rules do not contain new rules
           RoleData upgradedCaAdmRole = roleAccessSession.findRole(caAdmRoleName);
           assertEquals(4, upgradedCaAdmRole.getAccessRules().size());
           assertFalse(
                   "Role was upgraded with rule " + StandardRules.REGULAR_EDITAVAILABLEEKU.resource() + ", even though it shouldn't have.",
                   upgradedCaAdmRole.getAccessRules()
                           .containsValue(
                                   new AccessRuleData(caAdmRoleName, StandardRules.REGULAR_EDITAVAILABLEEKU.resource(),
                                           AccessRuleState.RULE_ACCEPT, false)));
           
           assertFalse(
                   "Role was not upgraded with rule " + StandardRules.REGULAR_EDITAVAILABLECUSTOMCERTEXTENSION.resource() + ", even though it shouldn't have.",
                   upgradedCaAdmRole.getAccessRules()
                           .containsValue(
                                   new AccessRuleData(caAdmRoleName, StandardRules.REGULAR_EDITAVAILABLECUSTOMCERTEXTENSION.resource(),
                                           AccessRuleState.RULE_ACCEPT, false)));


       } finally {
           roleManagementSession.remove(alwaysAllowtoken, sysConfigRoleName);
           roleManagementSession.remove(alwaysAllowtoken, caAdmRoleName);
       }
   }
   
   /**
    * This test will perform the upgrade step to 6.4.0 and tests whether the list of used certificate extension in a certificate profile was upgraded successfully. 
    * Prier to the upgrade, the used certificate extensions in a certificate profile were stored as a list of Integers representing the extensions' IDs. After 
    * upgrade, the used certificate extensions in a certificate profile are stored as a listed on Strings representing the extensions' OIDs.
    * @throws CertificateExtentionConfigurationException 
    * @throws AuthorizationDeniedException 
    * @throws CertificateProfileExistsException 
    */
   @Test
   public void testPostUpgradeTo640UsedCertExtensionsInCertProfile() throws CertificateExtentionConfigurationException, AuthorizationDeniedException, CertificateProfileExistsException {
       
       // Populate the available custom certificate extensions
       AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();
       Properties props = new Properties();
       props.put("translatable", "FALSE");
       props.put("encoding", "DERPRINTABLESTRING");
       props.put("value", "Test 123");
       cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION", BasicCertificateExtension.class.getName(), true, props);
       props = new Properties();
       props.put("translatable", "FALSE");
       props.put("encoding", "DERPRINTABLESTRING");
       props.put("value", "Test 123");
       cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, props);
       props = new Properties();
       props.put("translatable", "TRUE");
       props.put("value", "Test 321");
       cceConfig.addCustomCertExtension(3, "3.2.3.4", "TESTEXTENSION3", BasicCertificateExtension.class.getName(), false, props);
       globalConfigSession.saveConfiguration(alwaysAllowtoken, cceConfig);
       
       // If the test profile was not removed previously, remove it now
       String testCPName = "testCP";
       if(certProfileSession.getCertificateProfile(testCPName)!=null) {
           certProfileSession.removeCertificateProfile(alwaysAllowtoken, testCPName);
       }
       
       try {
           CertificateProfile testCP = new CertificateProfile();
           ArrayList<Integer> usedExts = new ArrayList<Integer>();
           usedExts.add(1);
           usedExts.add(3);
           testCP.setUsedCertificateExtensions(usedExts);
           certProfileSession.addCertificateProfile(alwaysAllowtoken, testCPName, testCP);
           
           // Check that the test profile contains the right values of used certificate extensions before upgrade
           testCP = null;
           testCP = certProfileSession.getCertificateProfile(testCPName);
           List oldUsedExts = testCP.getUsedCertificateExtensions();
           assertEquals(2, oldUsedExts.size());
           assertTrue(oldUsedExts.contains(1));
           assertFalse(oldUsedExts.contains(2));
           assertTrue(oldUsedExts.contains(3));
           
           // preform the upgrade
           upgradeSession.upgrade(null, "6.3.2", true);
           
           // Check that the test profile contains the right values of used certificate extensions after upgrade
           testCP = null;
           testCP = certProfileSession.getCertificateProfile(testCPName);
           List newUsedExts = testCP.getUsedCertificateExtensions();
           assertEquals(2, newUsedExts.size());
           assertTrue(newUsedExts.contains("1.2.3.4"));
           assertFalse(newUsedExts.contains("2.2.3.4"));
           assertTrue(newUsedExts.contains("3.2.3.4"));
       } finally {
           certProfileSession.removeCertificateProfile(alwaysAllowtoken, testCPName);
       }
   }
       
    
}
