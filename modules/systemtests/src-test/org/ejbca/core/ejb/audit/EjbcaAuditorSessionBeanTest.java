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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedDevice;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.management.RoleSessionRemote;
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
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    
    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaAuditorSessionBeanTest"));
    
    @Before
    public void setup() throws RoleExistsException, RoleNotFoundException {
        super.setUpAuthTokenAndRole(null, ROLE_NAME, Arrays.asList(AuditLogRules.VIEW.resource()), null);
    }

    @After
    public void tearDown() throws Exception {
        super.tearDownRemoveRole();
    }

    /**
     * Try to access audit logs with:
     * - a token that has not passed authentication checks
     * - is not authorized to AUDITLOGSELECT
     */
    @Test
    public void testAuthorization() throws RoleNotFoundException, AuthorizationDeniedException, RoleExistsException {
        LOG.trace(">testAuthorization");
        final Role roleAuditor = roleSession.getRole(alwaysAllowToken, null, ROLE_NAME);
        roleAuditor.getAccessRules().put(AuditLogRules.VIEW.resource(), Role.STATE_DENY);
        roleSession.persistRole(alwaysAllowToken, roleAuditor);
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
    
    private String getLongString() {
        StringBuilder sb = new StringBuilder();
        for(int i=0; i<400; i++) {
            sb.append(i%10);
        }
        return sb.toString();
    }
    
    @Test
    public void testAuthorizationBigName() throws RoleNotFoundException, AuthorizationDeniedException, RoleExistsException {
        LOG.trace(">testAuthorizationBigName");
        String upn = "EjbcaAuditorSessionBeanTest" + getLongString();
        AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(upn));
        final Role roleAuditor = roleSession.getRole(alwaysAllowToken, null, ROLE_NAME);
        roleAuditor.getAccessRules().put(AuditLogRules.CONFIGURE.resource(), Role.STATE_ALLOW);
        roleSession.persistRole(alwaysAllowToken, roleAuditor);
        final List<Object> params = new ArrayList<Object>();
        params.add(EventTypes.ACCESS_CONTROL.toString());
        List<? extends AuditLogEntry> entries = 
                ejbcaAuditorSession.selectAuditLog(roleMgmgToken, DEVICE_NAME, 0, 1, "a.eventType != ?0", "a.timeStamp DESC", params);
        
        assertEquals("Authtoken was not trimmed where subject is too big.", 
                entries.get(0).getAuthToken(), "[trimmed] " + upn.substring(0, 235));
        assertEquals("Authtoken is not part of additional details when subject is too big.", 
                                   entries.get(0).getMapAdditionalDetails().get("authToken"), upn);
        
        LOG.trace("<testAuthorizationBigName");
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
