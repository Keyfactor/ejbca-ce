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

package org.cesecore.roles.member;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;



/**
 * 
 * @version $Id$
 *
 */
public class RoleMemberSessionBeanTest extends RoleUsingTestCase {

    private static final Logger log = Logger.getLogger(RoleMemberSessionBeanTest.class);
    private static final int INVALID_USER_ID = -1;
    private RoleMemberSessionRemote roleMemberSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private RoleSessionRemote roleSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    
    private AuthenticationToken authenticationToken;
    private AuthenticationToken unauthorizedAuthenticationToken;
    
    private Role role;
    private Role persistedTestRole;
    private RoleMember roleMember;
    
    
    @Before
    public void setUp() throws RoleExistsException, RoleNotFoundException, AuthorizationDeniedException {
        final String unauthorizedDN = "CN=RoleMemberSessionBeanTest";
        setUpAuthTokenAndRole("RoleMemberSessionTest"); //Set up role authorized to create new roles
        authenticationToken = roleMgmgToken;
        unauthorizedAuthenticationToken = createAuthenticationToken(unauthorizedDN);
        
        //Create a new role used for tests only, makes cleanup easier
        role = new Role(null, "TestMembersRole");
        persistedTestRole = roleSessionRemote.persistRole(authenticationToken, role);
        
        roleMember = new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, "CertificateAuthenticationToken", RoleMember.NO_ISSUER, 0, 0, "",
                                    persistedTestRole.getRoleId(), "TestValue", "");
    }
    
    @After
    public void tearDown() throws AuthorizationDeniedException, RoleNotFoundException {
        final Role role = roleSessionRemote.getRole(authenticationToken, null, "TestMembersRole");
        if (role != null) {
            roleSessionRemote.deleteRoleIdempotent(authenticationToken, role.getRoleId());
        } else {
            log.info("Removing database test entries failed");
        }
        tearDownRemoveRole();
    }
    
    
    @Test
    public void testCreateOrEditRoleMember() throws AuthorizationDeniedException {
        int persistedMemberId = roleMemberSessionRemote.createOrEdit(authenticationToken, roleMember);
        RoleMember retrievedRoleMember = roleMemberSessionRemote.getRoleMember(authenticationToken, persistedMemberId);
        
        assertNotNull(retrievedRoleMember);
        assertEquals(persistedMemberId, retrievedRoleMember.getId());
        
        //Testing if editing a RoleMember updates rather than creating a new entry in DB.
        roleMember.setId(persistedMemberId);
        roleMember.setTokenMatchValue("EditedValue");
        
        int editedRoleMemberId = roleMemberSessionRemote.createOrEdit(authenticationToken, roleMember);
        assertEquals(persistedMemberId, editedRoleMemberId);
    }
    
    @Test
    public void testRemoveRoleMember() throws AuthorizationDeniedException {
        int persistedMemberId = roleMemberSessionRemote.createOrEdit(authenticationToken, roleMember);
        boolean isRemoved = roleMemberSessionRemote.remove(authenticationToken, persistedMemberId);
        assertNull(roleMemberSessionRemote.getRoleMember(authenticationToken, persistedMemberId));
        assertTrue(isRemoved);
        isRemoved = roleMemberSessionRemote.remove(authenticationToken, INVALID_USER_ID);
        assertFalse(isRemoved);
    }
    
    
    @Test
    public void testGetRoleMember() throws AuthorizationDeniedException {
        RoleMember retrievedMember;
        int persistedMemberId = roleMemberSessionRemote.createOrEdit(authenticationToken, roleMember);
        retrievedMember = roleMemberSessionRemote.getRoleMember(authenticationToken, persistedMemberId);
        assertNotNull(retrievedMember);
        retrievedMember = roleMemberSessionRemote.getRoleMember(authenticationToken, INVALID_USER_ID);
        assertNull(retrievedMember);
    }
    
    @Test
    public void testGetRoleMembersByRoleId() throws AuthorizationDeniedException {
        int numberOfTestEntries = 3;
        
        for (int i = 0; i < numberOfTestEntries; i++) {
            roleMemberSessionRemote.createOrEdit(authenticationToken, roleMember);
        }
        
        List<RoleMember> returnedRoleMembers = roleMemberSessionRemote.getRoleMembersByRoleId(authenticationToken, persistedTestRole.getRoleId());
        
        assertEquals(numberOfTestEntries, returnedRoleMembers.size());
        for (RoleMember roleMember : returnedRoleMembers) {
            assertEquals(persistedTestRole.getRoleId(), roleMember.getRoleId());
        }
    }
    
    @Test
    public void testAddAndRemoveRoleMembersToRole() {
        
    }
    
    
    
    //Authorization tests
    @Test(expected = AuthorizationDeniedException.class)
    public void testCreateOrEditUnauthorized() throws AuthorizationDeniedException {
        roleMemberSessionRemote.createOrEdit(unauthorizedAuthenticationToken, roleMember);
    }
     
    @Test(expected = AuthorizationDeniedException.class)
    public void testRemoveUnauthorized() throws AuthorizationDeniedException {
        int persistedMemberId = roleMemberSessionRemote.createOrEdit(authenticationToken, roleMember);
        roleMemberSessionRemote.remove(unauthorizedAuthenticationToken, persistedMemberId);
    }
    
    @Test(expected = AuthorizationDeniedException.class)
    public void testGetRoleMemberUnauthorized() throws AuthorizationDeniedException {
        int persistedMemberId = roleMemberSessionRemote.createOrEdit(authenticationToken, roleMember);
        roleMemberSessionRemote.getRoleMember(unauthorizedAuthenticationToken, persistedMemberId);
    }
    
    @Test(expected = AuthorizationDeniedException.class)
    public void testGetMembersByIdUnauthorized() throws AuthorizationDeniedException {
        roleMemberSessionRemote.getRoleMembersByRoleId(unauthorizedAuthenticationToken, INVALID_USER_ID);
    }
    
    

}


