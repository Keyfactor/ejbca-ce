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

package org.ejbca.webtest;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AdminRolesHelper;
import org.ejbca.test.utils.ConfigurationConstants;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;


@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa67_AccessRuleSorted extends WebTestBase {
    
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));
    private static final String roleName = "ECAQA67_TestRole";
    
    private static WebDriver webDriver;
    private static RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
 
    @BeforeClass
    public static void init() {
        setUp(true, ConfigurationConstants.PROFILE_FIREFOX_SUPERADMIN);
        webDriver = getWebDriver();
    }
    
    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        webDriver.quit();
        Role role = roleSession.getRole(admin, null, roleName);
        roleSession.deleteRoleIdempotent(admin, role.getRoleId());
    }
    
    @Test
    public void testA_addRoleAndEditRules() {
        AdminRolesHelper.goTo(webDriver, getAdminWebUrl());
        AdminRolesHelper.addRole(webDriver, roleName, true);
        AdminRolesHelper.editAccessRules(webDriver, roleName);
        webDriver.findElement(By.xpath("//tr/td/a[text()='Advanced Mode']")).click();
    }
    
    @Test
    public void testB_assertOrdering() {
        List<String> displayedRulesOrder;
        List<String> sortedRules;
        List<WebElement> ruleGroups = webDriver.findElements(By.xpath("//td/table[@class='fullwidth']"));
        for (WebElement ruleGroup : ruleGroups) {
            displayedRulesOrder = new ArrayList<>();
            String groupName = ruleGroup.findElement(By.xpath(".//thead/tr/th")).getText();
            List<WebElement> rows = ruleGroup.findElements(By.xpath(".//td[@class='rulesColumn1 alignmiddle']"));
            for (WebElement row : rows) {
                displayedRulesOrder.add(row.getText());
            }
            sortedRules = new ArrayList<>();
            sortedRules.addAll(displayedRulesOrder);
            sortIgnoreCase(sortedRules);
            assertEquals(groupName + " was not sorted alphabetically", sortedRules, displayedRulesOrder);
        }
    }
    
    private void sortIgnoreCase(List<String> rulesToSort) {
        Collections.sort(rulesToSort, new Comparator<String>() {
            @Override
            public int compare(String first, String second) {
                return first.compareToIgnoreCase(second);
            }

        });
    }
}