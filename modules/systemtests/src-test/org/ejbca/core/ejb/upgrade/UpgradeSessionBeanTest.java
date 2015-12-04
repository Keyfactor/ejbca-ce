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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.model.authorization.AccessRuleTemplate;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.DefaultRoles;
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
    public void testPostUpgradeTo640AuditorRole() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
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
            upgradeSession.upgrade(null, "6.3.2", false);
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
       oldSysConfigAccessRules.add(new AccessRuleData(sysConfigRole.getRoleName(), StandardRules.SYSTEMCONFIGURATION_EDIT.resource(), AccessRuleState.RULE_ACCEPT, false));
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
           upgradeSession.upgrade(null, "6.3.2", false);
           
           // Verify that sysConfigRole's access rules contained rules to edit available extended key usages and custom certificate extensions
           RoleData upgradedSysConfigRole = roleAccessSession.findRole(sysConfigRoleName);
           assertEquals(6, upgradedSysConfigRole.getAccessRules().size());
           assertTrue(
                   "Role was not upgraded with rule " + StandardRules.SYSTEMCONFIGURATION_EDIT.resource(),
                   upgradedSysConfigRole.getAccessRules().containsValue(
                           new AccessRuleData(sysConfigRoleName, StandardRules.SYSTEMCONFIGURATION_EDIT.resource(), AccessRuleState.RULE_ACCEPT, false)));
           assertTrue(
                   "Role was not upgraded with rule " + StandardRules.EKUCONFIGURATION_EDIT.resource(),
                   upgradedSysConfigRole.getAccessRules()
                           .containsValue(
                                   new AccessRuleData(sysConfigRoleName, StandardRules.EKUCONFIGURATION_EDIT.resource(),
                                           AccessRuleState.RULE_ACCEPT, false)));
           
           assertTrue(
                   "Role was not upgraded with rule " + StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource(),
                   upgradedSysConfigRole.getAccessRules()
                           .containsValue(
                                   new AccessRuleData(sysConfigRoleName, StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource(),
                                           AccessRuleState.RULE_ACCEPT, false)));
           
           
           
           // Verify that caAdmRole's access rules do not contain new rules
           RoleData upgradedCaAdmRole = roleAccessSession.findRole(caAdmRoleName);
           assertEquals(4, upgradedCaAdmRole.getAccessRules().size());
           assertFalse(
                   "Role was upgraded with rule " + StandardRules.EKUCONFIGURATION_EDIT.resource() + ", even though it shouldn't have.",
                   upgradedCaAdmRole.getAccessRules()
                           .containsValue(
                                   new AccessRuleData(caAdmRoleName, StandardRules.EKUCONFIGURATION_EDIT.resource(),
                                           AccessRuleState.RULE_ACCEPT, false)));
           
           assertFalse(
                   "Role was not upgraded with rule " + StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource() + ", even though it shouldn't have.",
                   upgradedCaAdmRole.getAccessRules()
                           .containsValue(
                                   new AccessRuleData(caAdmRoleName, StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource(),
                                           AccessRuleState.RULE_ACCEPT, false)));


       } finally {
           roleManagementSession.remove(alwaysAllowtoken, sysConfigRoleName);
           roleManagementSession.remove(alwaysAllowtoken, caAdmRoleName);
       }
   }
   
   @Test
   public void testVersionUtil() throws NoSuchMethodException, SecurityException, IllegalAccessException, InvocationTargetException, IllegalArgumentException, InstantiationException {
       assertTrue("Version util did not parse correctly.", isLesserThan("1", "2"));
       assertFalse("Version util did not parse correctly.", isLesserThan("2", "1"));
       assertTrue("Version util did not parse correctly.", isLesserThan("1.0", "2.0"));
       assertTrue("Version util did not parse correctly.", isLesserThan("2.0", "2.1"));
       assertFalse("Version util did not parse correctly.", isLesserThan("1.0", "1.0"));
       assertTrue("Version util did not parse correctly.", isLesserThan("2.0.0", "2.1"));
       assertTrue("Version util did not parse correctly.", isLesserThan("2.1", "2.1.1"));
   }
   
    private boolean isLesserThan(String firstVersion, String secondVersion) throws IllegalAccessException, InvocationTargetException,
            NoSuchMethodException, SecurityException, IllegalArgumentException, InstantiationException {
        Method upgradeMethod = UpgradeSessionBean.class.getDeclaredMethod("isLesserThan", String.class, String.class);
        upgradeMethod.setAccessible(true);
        return (Boolean) upgradeMethod.invoke(UpgradeSessionBean.class.newInstance(), firstVersion, secondVersion);
    }
    
    /**
     * This test checks the automatic upgrade to 6.4.2, namely that:
     * 
     * 1. Auditors are given the new default rights introduced in 6.4.2
     * 2. That roles that had edit access to pages that have been given read rights now also have read rights. 
     * @throws AuthorizationDeniedException 
     * @throws RoleExistsException 
     * @throws RoleNotFoundException 
     */
    @Test
    public void testUpgradeTo642AuditorRole() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
        final String oldAuditorName = "640Auditor"; 
        final String editSystemAdminName = "EditSystemAdmin";
        RoleData oldAuditor = roleManagementSession.create(alwaysAllowtoken, oldAuditorName);
        RoleData editSystemAdmin = roleManagementSession.create(alwaysAllowtoken, editSystemAdminName);
        try {
            Set<String> newRules = new HashSet<String>();
            newRules.add(StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
            newRules.add(StandardRules.EKUCONFIGURATION_VIEW.resource());
            newRules.add(StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource());
            newRules.add(StandardRules.VIEWROLES.resource());
            newRules.add(AccessRulesConstants.REGULAR_VIEWENDENTITY);
            //Create an auditor according to 6.4.0, i.e. ignoring the new rules.
            List<AccessRuleData> oldAuditorRules = new ArrayList<AccessRuleData>();
            for (AccessRuleTemplate accessRuleTemplate : DefaultRoles.AUDITOR.getRuleSet()) {
                if (!newRules.contains(accessRuleTemplate.getAccessRuleName())) {
                    oldAuditorRules.add(new AccessRuleData(oldAuditorName, accessRuleTemplate.getAccessRuleName(), accessRuleTemplate.getState(),
                            accessRuleTemplate.isRecursive()));
                }
            }
            oldAuditor = roleManagementSession.addAccessRulesToRole(alwaysAllowtoken, oldAuditor, oldAuditorRules);
            //Confirm that auditor doesn't have access to rules prematurely
            for (String newRule : newRules) {
                if (oldAuditor.hasAccessToRule(newRule)) {
                    throw new IllegalStateException("6.4.0 auditor had access to rule " + newRule + ", test is invalid.");
                }
            }
            //Create an auditor with access to the old edit rules. 
            List<AccessRuleData> oldEditAdminRules = new ArrayList<AccessRuleData>();
            oldEditAdminRules.add(new AccessRuleData(editSystemAdminName, StandardRules.SYSTEMCONFIGURATION_EDIT.resource(), AccessRuleState.RULE_ACCEPT, false));
            oldEditAdminRules.add(new AccessRuleData(editSystemAdminName, StandardRules.EKUCONFIGURATION_EDIT.resource(), AccessRuleState.RULE_ACCEPT, false));
            oldEditAdminRules.add(new AccessRuleData(editSystemAdminName, StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource(), AccessRuleState.RULE_ACCEPT, false));
            oldEditAdminRules.add(new AccessRuleData(editSystemAdminName, StandardRules.EDITROLES.resource(), AccessRuleState.RULE_ACCEPT, false));
            editSystemAdmin = roleManagementSession.addAccessRulesToRole(alwaysAllowtoken, editSystemAdmin, oldEditAdminRules);
            //Perform upgrade. 
            upgradeSession.upgrade(null, "6.4.0", false);
            RoleData upgradedAuditor = roleAccessSession.findRole(oldAuditorName);
            RoleData upgradedEditSystemAdmin = roleAccessSession.findRole(editSystemAdminName);
            for (String newRule : newRules) {
                assertTrue("6.4.0 Auditor role should have been given access to rule " + newRule + " during upgrade.",
                        upgradedAuditor.hasAccessToRule(newRule));
                if (!newRule.equals(AccessRulesConstants.REGULAR_VIEWENDENTITY)) {
                    assertTrue("Role with edit right should have been given access to rule " + newRule + " during upgrade.",
                            upgradedEditSystemAdmin.hasAccessToRule(newRule));
                }
            }
        } finally {
            try {
                roleManagementSession.remove(alwaysAllowtoken, oldAuditorName);
            } catch (RoleNotFoundException e) {
                // NOPMD Ignore
            }
            try {
                roleManagementSession.remove(alwaysAllowtoken, editSystemAdminName);
            } catch (RoleNotFoundException e) {
                // NOPMD Ignore
            }
        }
    }
    
    
}
