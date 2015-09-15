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

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
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

    private AuthenticationToken alwaysAllowtoken = new TestAlwaysAllowLocalAuthenticationToken("UpgradeSessionBeanTest");
    
    /**
     * This test will perform the upgrade step to 6.3.3, which is update of access rules, adding read-only rules to any roles which previously had them.
     * 
     */
    @Test
    public void testPostUpgradeTo633() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
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

}
