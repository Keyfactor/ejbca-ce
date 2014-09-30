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
package org.ejbca.core.ejb.audit;

import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedDevice;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleNotFoundException;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * System test of EjbcaAuditorSessionBean through remote proxy.
 * 
 * @version $Id$
 */
public class EjbcaAuditorSessionBeanTest extends RoleUsingTestCase {
    
    private static final Logger LOG = Logger.getLogger(EjbcaAuditorSessionBeanTest.class);
    private final static String DEVICE_NAME = IntegrityProtectedDevice.class.getSimpleName();
    private final static String ROLE_NAME = "EjbcaSecurityAuditTest";
    
    private EjbcaAuditorTestSessionRemote ejbcaAuditorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EjbcaAuditorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    
    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaAuditorSessionBeanTest"));
    
    @Before
    public void setup() throws RoleExistsException, RoleNotFoundException, AccessRuleNotFoundException, AuthorizationDeniedException {
        // Set up base role that can edit roles
        setUpAuthTokenAndRole(ROLE_NAME);
        // Now we have a role that can edit roles, we can edit this role to include more privileges
        final RoleData role = roleAccessSession.findRole(ROLE_NAME);
        // Add rules to the role, for the resource
        final List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), AuditLogRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(alwaysAllowToken, role, accessRules);
    }

    @After
    public void tearDown() throws Exception {
        tearDownRemoveRole();
    }

    /**
     * Try to access audit logs with:
     * - a token that has not passed authentication checks
     * - is not authorized to AUDITLOGSELECT
     */
    @Test
    public void testAuthorization() throws RoleNotFoundException, AuthorizationDeniedException {
        LOG.trace(">testAuthorization");
        final RoleData role = roleAccessSession.findRole(ROLE_NAME);
        final List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(ROLE_NAME, AuditLogRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.removeAccessRulesFromRole(alwaysAllowToken, role, accessRules);
        //Create a brand spanking new authenticationToken
        AuthenticationToken authenticationToken = createAuthenticationToken("CN="+ROLE_NAME);
        try {
            ejbcaAuditorSession.selectAuditLog(authenticationToken, DEVICE_NAME, 0, 10, null, null, null);
            fail("Authorization was not denied!");
        } catch (AuthorizationDeniedException e) {
            // Expected
            LOG.debug(e.getMessage());
        }
        LOG.trace("<testAuthorization");
    }
    
    @Test
    public void testHappyPaths() throws AuthorizationDeniedException {
        LOG.trace(">testHappyPaths");
        final List<Object> params = new ArrayList<Object>();
        params.add(EventTypes.ACCESS_CONTROL.toString());
        // Select without where or order
        ejbcaAuditorSession.selectAuditLog(roleMgmgToken, DEVICE_NAME, 0, 10, null, null, null);
        ejbcaAuditorSession.selectAuditLog(roleMgmgToken, DEVICE_NAME, 0, 10, "", "", null);
        // Select without order
        ejbcaAuditorSession.selectAuditLog(roleMgmgToken, DEVICE_NAME, 0, 10, "a.eventType != ?0", null, params);
        ejbcaAuditorSession.selectAuditLog(roleMgmgToken, DEVICE_NAME, 0, 10, "a.eventType != ?0", "", params);
        // Select without where
        ejbcaAuditorSession.selectAuditLog(roleMgmgToken, DEVICE_NAME, 0, 10, null, "a.timeStamp DESC", null);
        ejbcaAuditorSession.selectAuditLog(roleMgmgToken, DEVICE_NAME, 0, 10, "", "a.timeStamp DESC", null);
        // Select with both where and order
        ejbcaAuditorSession.selectAuditLog(roleMgmgToken, DEVICE_NAME, 0, 10, "a.eventType != ?0", "a.timeStamp DESC", params);
        // Select with both multiple where and order
        params.add("superadmin");  // searchDetail2 is mapped to username
        ejbcaAuditorSession.selectAuditLog(roleMgmgToken, DEVICE_NAME, 0, 10, "a.eventType != ?0 AND a.searchDetail2 != ?1", "a.timeStamp DESC", params);
        LOG.trace("<testHappyPaths");
    }
    
    @Test
    public void testBadOrder() {
        LOG.trace(">testBadOrder");
        assertBadOrderFailure(" ");
        assertBadOrderFailure("; drop database ejbca;");
        assertBadOrderFailure("a.timeStamp DESC, a.eventType DESC"); // We don't allow multiple ORDER BYs currently
        assertBadOrderFailure("=");
        LOG.trace("<testBadOrder");
    }

    private void assertBadOrderFailure(final String orderClause) {
        LOG.trace(">assertBadOrderFailure");
        try {
            ejbcaAuditorSession.selectAuditLog(roleMgmgToken, DEVICE_NAME, 0, 10, null, orderClause, null);
            fail("Was able to select using bad order clause!");
        } catch (AuthorizationDeniedException e) {
            fail("Authorization was denied!");
        } catch (Exception e) {
            // Expected, catch wide since different app servers throw differently, i.e. glassfish wraps in EJBException
            LOG.debug(e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        LOG.trace("<assertBadOrderFailure");
    }
    
    @Test
    public void testBadWhere() {
        LOG.trace(">testBadWhere");
        assertBadWhereFailure(" ", null);
        assertBadWhereFailure("1=1; drop database ejbca;", null);
        // Assert parameter mismatch leads to failure
        assertBadWhereFailure("a.eventType != ?0", null);
        final List<Object> params = new ArrayList<Object>();
        assertBadWhereFailure("a.eventType != ?0", params);
        params.add(EventTypes.ACCESS_CONTROL.toString());
        params.add(EventTypes.ACCESS_CONTROL.toString());
        assertBadWhereFailure("a.eventType != ?0", params);
        LOG.trace("<testBadWhere");
    }

    private void assertBadWhereFailure(final String whereClause, final List<Object> parameters) {
        LOG.trace(">assertBadWhereFailure");
        try {
            ejbcaAuditorSession.selectAuditLog(roleMgmgToken, DEVICE_NAME, 0, 10, whereClause, null, parameters);
            fail("Was able to select using bad where clause!");
        } catch (AuthorizationDeniedException e) {
            fail("Authorization was denied!");
        } catch (Exception e) {
            // Expected, catch wide since different app servers throw differently, i.e. glassfish wraps in EJBException
            LOG.debug(e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        LOG.trace("<assertBadWhereFailure");
    }
}
