/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.audit;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.cesecore.RoleUsingTestCase;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.junit.After;
import org.junit.Before;

/**
 * 
 * @version $Id$
 *
 */

public abstract class SecurityEventsBase extends RoleUsingTestCase {

    public static final String keyAlias = "secretkey";
    public static final String tokenPin = "userpin";
    public static final String keyPairAlgorithm = "1024";
    public static final String keyPairSignAlgorithm = "SHA512withRSA";

    protected RoleAccessSessionRemote roleAccessSession = JndiHelper.getRemoteSession(RoleAccessSessionRemote.class);
    protected RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);

    public static final CryptoToken createTokenWithKeyPair() throws Exception {

        Properties props = new Properties();
        props.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, tokenPin);

        CryptoToken token = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), props, null, 1);
        token.activate(tokenPin.toCharArray());
        token.generateKeyPair(keyPairAlgorithm, keyAlias);

        return token;
    }

    @Before
    public void setUp() throws Exception{
    	// Set up base role that can edit roles
    	setUpAuthTokenAndRole("SecurityAuditTest");

    	// Now we have a role that can edit roles, we can edit this role to include more privileges
    	RoleData role = roleAccessSession.findRole("SecurityAuditTest");

        // Add rules to the role, for the resource
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.AUDITLOGEXPORT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.AUDITLOGVERIFY.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.AUDITLOGSELECT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.AUDITLOGMANAGE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.AUDITLOGLOG.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(roleMgmgToken, role, accessRules);
    }

    @After
    public void tearDown() throws Exception {
    	tearDownRemoveRole();
    }

}
