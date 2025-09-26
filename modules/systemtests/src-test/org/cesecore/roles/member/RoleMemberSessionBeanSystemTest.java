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

import java.util.List;

import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.dto.RoleDataDto;
import org.cesecore.dto.RoleDataDtoBuilder;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Test of RoleMemberSessionBean.
 *
 */
public class RoleMemberSessionBeanSystemTest extends RoleUsingTestCase {

    private static final int INVALID_USER_ID = -1;
    private static final String NAME_SPACE = null;
    private static final String ROLE_NAME = "TestMembersRole";
    private static final String ROLE_MEMBER_NAME = "RoleMemberSessionTest";
    private AuthenticationToken alwaysAllowToken;

    private RoleMemberSessionRemote roleMemberSessionRemote;
    private RoleSessionRemote roleSessionRemote;
    
    private AuthenticationToken authenticationToken;
    private AuthenticationToken unauthorizedAuthenticationToken;

    private RoleDataDto role;
    private RoleDataDto persistedTestRole;
    private RoleMember roleMember;

    @Before
    public void setUp() throws RoleExistsException, RoleNotFoundException, AuthorizationDeniedException, InterruptedException {
        alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(this.getClass().getSimpleName());
        roleMemberSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
        roleSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
        cleanUpRole(NAME_SPACE, ROLE_NAME);
        cleanUpRole(NAME_SPACE, ROLE_MEMBER_NAME);
        final String unauthorizedDN = "CN=RoleMemberSessionBeanSystemTest";
        setUpAuthTokenAndRole(ROLE_MEMBER_NAME); //Set up role authorized to create new roles
        authenticationToken = roleMgmgToken;
        unauthorizedAuthenticationToken = createAuthenticationToken(unauthorizedDN);

        // Create a new role used for tests only, makes cleanup easier
        role = new RoleDataDtoBuilder().setName(ROLE_NAME).build();
        persistedTestRole = roleSessionRemote.persistRole(authenticationToken, role);
        roleMember = new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, RoleMember.NO_ISSUER, RoleMember.NO_PROVIDER, X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(), "foo",
                                    persistedTestRole.getId(), "TestValue");
    }
    
    @After
    public void tearDown() throws AuthorizationDeniedException, RoleNotFoundException {
        tearDownRemoveRole();
        cleanUpRole(NAME_SPACE, ROLE_NAME);
        cleanUpRole(NAME_SPACE, ROLE_MEMBER_NAME);
    }
    
    private void cleanUpRole(final String nameSpace, final String roleName) throws AuthorizationDeniedException {
        final RoleDataDto cleanUpRole = roleSessionRemote.getRole(alwaysAllowToken, nameSpace, roleName);
        if (cleanUpRole != null) {
            roleSessionRemote.deleteRoleIdempotent(alwaysAllowToken, cleanUpRole.id());
        }
    }
 
    /**
     * When adding a null RoleMember, nothing is expected to happen and no exceptions should
     * be thrown unless AuthenticationToken is denied
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testAddNullRoleMember() throws AuthorizationDeniedException {
        RoleMember nullMember = null;
        nullMember = roleMemberSessionRemote.persist(authenticationToken, nullMember);
        assertNull(nullMember);
    }
    
    /**
     * Tests behavior while creating, editing and persisting roles.
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testCreateOrEditRoleMember() throws AuthorizationDeniedException {
        final RoleMember persistedRoleMember = roleMemberSessionRemote.persist(authenticationToken, this.roleMember);
        final RoleMember retrievedRoleMember = roleMemberSessionRemote.getRoleMember(authenticationToken, persistedRoleMember.getId());
        assertNotNull(persistedRoleMember);
        assertNotNull(retrievedRoleMember);
        assertEquals(persistedRoleMember.getId(), retrievedRoleMember.getId());
        
        //Testing if editing a RoleMember updates rather than creating a new entry in DB.
        this.roleMember.setId(persistedRoleMember.getId());
        final String NEWTOKENMATCHVALUE = "EditedValue";
        this.roleMember.setTokenMatchValue(NEWTOKENMATCHVALUE);
        
        final RoleMember editedRoleMember = roleMemberSessionRemote.persist(authenticationToken, this.roleMember);
        assertEquals(persistedRoleMember.getId(), editedRoleMember.getId());
        assertEquals(NEWTOKENMATCHVALUE, editedRoleMember.getTokenMatchValue());
    }
    
    /**
     * Verifies if removed roles are deleted permanently
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testRemoveRoleMember() throws AuthorizationDeniedException {
        final RoleMember persistedRoleMember = roleMemberSessionRemote.persist(authenticationToken, this.roleMember);
        boolean isRemoved = roleMemberSessionRemote.remove(authenticationToken, persistedRoleMember.getId());
        assertNull(roleMemberSessionRemote.getRoleMember(authenticationToken, persistedRoleMember.getId()));
        assertTrue(isRemoved);
        isRemoved = roleMemberSessionRemote.remove(authenticationToken, INVALID_USER_ID);
        assertFalse(isRemoved);
    }

    /**
     * Simple retrieve test. Accessing roles members in database
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testGetRoleMember() throws AuthorizationDeniedException {
        final RoleMember persistedRoleMember = roleMemberSessionRemote.persist(authenticationToken, this.roleMember);
        RoleMember retrievedMember = roleMemberSessionRemote.getRoleMember(authenticationToken, persistedRoleMember.getId());
        assertNotNull(retrievedMember);
        retrievedMember = roleMemberSessionRemote.getRoleMember(authenticationToken, INVALID_USER_ID);
        assertNull(retrievedMember);
    }
    
    /**
     * Tests if all role members belonging to a role are retrieved correctly on query
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testGetRoleMembersByRoleId() throws AuthorizationDeniedException {
        final int numberOfTestEntries = 3;
        for (int i = 0; i < numberOfTestEntries; i++) {
            roleMemberSessionRemote.persist(authenticationToken, roleMember);
        }
        List<RoleMember> returnedRoleMembers = roleMemberSessionRemote.getRoleMembersByRoleId(authenticationToken, persistedTestRole.id());
        assertEquals(numberOfTestEntries, returnedRoleMembers.size());
        for (RoleMember roleMember : returnedRoleMembers) {
            assertEquals(persistedTestRole.id().intValue(), roleMember.getRoleId());
        }
    }
    
    @Test
    public void testNormalization() throws AuthorizationDeniedException {
        RoleMember testRoleMember = roleMemberSessionRemote.persist(authenticationToken, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                RoleMember.NO_ISSUER, RoleMember.NO_PROVIDER, X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                "0", persistedTestRole.id(), "Test"));
        try {
            testRoleMember = roleMemberSessionRemote.getRoleMember(authenticationToken, testRoleMember.getId());
            assertEquals("0", testRoleMember.getTokenMatchValue());
            
            testRoleMember.setTokenMatchValue("0abc");
            roleMemberSessionRemote.persist(authenticationToken, testRoleMember);
            testRoleMember = roleMemberSessionRemote.getRoleMember(authenticationToken, testRoleMember.getId());
            assertEquals("ABC", testRoleMember.getTokenMatchValue());
            
            testRoleMember.setTokenMatchValue("000001000");
            roleMemberSessionRemote.persist(authenticationToken, testRoleMember);
            testRoleMember = roleMemberSessionRemote.getRoleMember(authenticationToken, testRoleMember.getId());
            assertEquals("1000", testRoleMember.getTokenMatchValue());
            
            testRoleMember.setTokenMatchValue("00000000");
            roleMemberSessionRemote.persist(authenticationToken, testRoleMember);
            testRoleMember = roleMemberSessionRemote.getRoleMember(authenticationToken, testRoleMember.getId());
            assertEquals("0", testRoleMember.getTokenMatchValue());
            
            // Only serial numbers should be normalized
            testRoleMember.setTokenMatchKey(X500PrincipalAccessMatchValue.WITH_UID.getNumericValue());
            testRoleMember.setTokenMatchValue("00000000");
            roleMemberSessionRemote.persist(authenticationToken, testRoleMember);
            testRoleMember = roleMemberSessionRemote.getRoleMember(authenticationToken, testRoleMember.getId());
            assertEquals("00000000", testRoleMember.getTokenMatchValue());
        } finally {
            roleMemberSessionRemote.remove(authenticationToken, testRoleMember.getId());
        }
    }
    
    //Authorization tests
    @Test(expected = AuthorizationDeniedException.class)
    public void testCreateOrEditUnauthorized() throws AuthorizationDeniedException {
        roleMemberSessionRemote.persist(unauthorizedAuthenticationToken, this.roleMember);
    }
     
    @Test(expected = AuthorizationDeniedException.class)
    public void testRemoveUnauthorized() throws AuthorizationDeniedException {
        final RoleMember roleMember = roleMemberSessionRemote.persist(authenticationToken, this.roleMember);
        roleMemberSessionRemote.remove(unauthorizedAuthenticationToken, roleMember.getId());
    }
    
    @Test(expected = AuthorizationDeniedException.class)
    public void testGetRoleMemberUnauthorized() throws AuthorizationDeniedException {
        final RoleMember roleMember = roleMemberSessionRemote.persist(authenticationToken, this.roleMember);
        roleMemberSessionRemote.getRoleMember(unauthorizedAuthenticationToken, roleMember.getId());
    }
    
    @Test(expected = AuthorizationDeniedException.class)
    public void testGetMembersByIdUnauthorized() throws AuthorizationDeniedException {
        roleMemberSessionRemote.getRoleMembersByRoleId(unauthorizedAuthenticationToken, INVALID_USER_ID);
    }
}
