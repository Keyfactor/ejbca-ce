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
package org.ejbca.core.ejb.hardtoken;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.apache.log4j.Logger;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleInitializationSessionRemote;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Tests the Hard Token Issuer entity bean.
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HardTokenIssuerTest extends RoleUsingTestCase {
    private static Logger log = Logger.getLogger(HardTokenIssuerTest.class);
    
    private HardTokenSessionRemote hardTokenSession = EjbRemoteHelper.INSTANCE.getRemoteSession(HardTokenSessionRemote.class);
    private RoleInitializationSessionRemote roleInitializationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken("HardTokenIssuerTest");

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void test01AddHardTokenIssuer() throws Exception {
        log.trace(">test01AddHardTokenIssuer()");
        boolean ret = false;
        HardTokenIssuer issuer = new HardTokenIssuer();
        issuer.setDescription("TEST");
        ret = hardTokenSession.addHardTokenIssuer(internalAdmin, "TEST", 3, issuer);
        assertTrue("Creating Hard Token Issuer failed", ret);
        HardTokenIssuerInformation data = hardTokenSession.getHardTokenIssuerInformation("TEST");
        assertEquals("TEST", data.getHardTokenIssuer().getDescription());
        log.trace("<test01AddHardTokenIssuer()");
    }

    @Test
    public void test02RenameHardTokenIssuer() throws Exception {
        log.trace(">test02RenameHardTokenIssuer()");
        boolean ret = false;
        ret = hardTokenSession.renameHardTokenIssuer(internalAdmin, "TEST", "TEST2", 4);
        assertTrue("Renaming Hard Token Issuer failed", ret);
        HardTokenIssuerInformation data = hardTokenSession.getHardTokenIssuerInformation("TEST2");
        assertEquals("TEST", data.getHardTokenIssuer().getDescription());
        data = hardTokenSession.getHardTokenIssuerInformation("TEST");
        assertNull(data);
        log.trace("<test02RenameHardTokenIssuer()");
    }

    @Test
    public void test03CloneHardTokenIssuer() throws Exception {
        log.trace(">test03CloneHardTokenIssuer()");
        // First test the clone operation on the object (pure JUnit test)
        HardTokenIssuer issuer = new HardTokenIssuer();
        issuer.setDescription("TEST");
        HardTokenIssuer issuer2 = (HardTokenIssuer)issuer.clone();
        assertEquals("TEST", issuer.getDescription());
        assertEquals("TEST", issuer2.getDescription());
        issuer.setDescription("TEST2");
        assertEquals("TEST2", issuer.getDescription());
        assertEquals("TEST", issuer2.getDescription());
        // Next do the test using the session bean
        boolean ret = false;
        ret = hardTokenSession.cloneHardTokenIssuer(internalAdmin, "TEST2", "TEST", 4);
        assertTrue("Cloning hard token issuer failed", ret);
        HardTokenIssuerInformation data = hardTokenSession.getHardTokenIssuerInformation("TEST2");
        assertEquals("TEST", data.getHardTokenIssuer().getDescription());
        data = hardTokenSession.getHardTokenIssuerInformation("TEST");
        assertEquals("TEST", data.getHardTokenIssuer().getDescription());

        log.trace("<test03CloneHardTokenIssuer()");
    }


    @Test
    public void test04EditHardTokenIssuer() throws Exception {
        log.trace(">test04EditHardTokenIssuer()");
        boolean ret = false;
        HardTokenIssuerInformation issuerdata = hardTokenSession.getHardTokenIssuerInformation("TEST");
        assertTrue("Retrieving HardTokenIssuer failed", issuerdata.getHardTokenIssuer().getDescription().equals("TEST"));
        issuerdata.getHardTokenIssuer().setDescription("TEST2");
        ret = hardTokenSession.changeHardTokenIssuer(internalAdmin, "TEST", issuerdata.getHardTokenIssuer());
        assertTrue("Editing HardTokenIssuer failed", ret);
        HardTokenIssuerInformation data = hardTokenSession.getHardTokenIssuerInformation("TEST");
        assertEquals("TEST2", data.getHardTokenIssuer().getDescription());
        log.trace("<test04EditHardTokenIssuer()");
    }

    @Test
    public void test05removeHardTokenIssuers() throws Exception {
        log.trace(">test05removeHardTokenIssuers()");
        try {
            hardTokenSession.removeHardTokenIssuer(internalAdmin, "TEST");
            hardTokenSession.removeHardTokenIssuer(internalAdmin, "TEST2");
        } catch (Exception pee) {
            fail("Removing HardTokenIssuers failed: " + pee.getMessage());
        }
        log.trace("<test05removeHardTokenIssuers()");
    }

    @Test
    public void testIsAuthorizedToHardTokenIssuer() throws Exception {
        final String rolename = "testGetAuthorizedToHardTokenIssuer";
        super.setUpAuthTokenAndRole(null, rolename, Arrays.asList(AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS),
                Arrays.asList(AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS));
        TestX509CertificateAuthenticationToken admin = roleMgmgToken;
        final String alias = "spacemonkeys";
        try {
            int roleId = roleSession.getRole(internalAdmin, null, rolename).getRoleId();
            {
                // Do legacy setup for now. Kill this during clean up.
                roleId = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class).findRole(rolename).getPrimaryKey();
            }
            HardTokenIssuer issuer = new HardTokenIssuer();
            issuer.setDescription(alias);
            if (!hardTokenSession.addHardTokenIssuer(internalAdmin, alias, roleId, issuer)) {
                fail("Could not add hard token issuer, test can not continue");
            }
            assertTrue(hardTokenSession.isAuthorizedToHardTokenIssuer(admin, alias));
            
            // Test authorization to edit with an unauthorized admin
            try {
                hardTokenSession.addHardTokenIssuer(admin, alias, roleId, issuer);
                fail("admin should not have been authorized to edit issuer");
            } catch (AuthorizationDeniedException e) {
                assertEquals("Administrator is not authorized to resource /hardtoken_functionality/edit_hardtoken_issuers. Msg: .", e.getMessage());
            }
            // Test authorization to edit with an unauthorized admin
            try {
                hardTokenSession.changeHardTokenIssuer(admin, alias, issuer);
                fail("admin should not have been authorized to edit issuer");
            } catch (AuthorizationDeniedException e) {
                assertEquals("Administrator is not authorized to resource /hardtoken_functionality/edit_hardtoken_issuers. Msg: .", e.getMessage());
            }
            // Test authorization to edit with an unauthorized admin
            try {
                hardTokenSession.cloneHardTokenIssuer(admin, alias, "newmonkeys", 1);
                fail("admin should not have been authorized to edit issuer");
            } catch (AuthorizationDeniedException e) {
                assertEquals("Administrator is not authorized to resource /hardtoken_functionality/edit_hardtoken_issuers. Msg: .", e.getMessage());
            }
            // Test authorization to edit with an unauthorized admin
            try {
                hardTokenSession.removeHardTokenIssuer(admin, alias);
                fail("admin should not have been authorized to edit issuer");
            } catch (AuthorizationDeniedException e) {
                assertEquals("Administrator is not authorized to resource /hardtoken_functionality/edit_hardtoken_issuers. Msg: .", e.getMessage());
            }
            // Test authorization to edit with an unauthorized admin
            try {
                hardTokenSession.renameHardTokenIssuer(admin, alias, "renamedmonkey", 1);
                fail("admin should not have been authorized to edit issuer");
            } catch (AuthorizationDeniedException e) {
                assertEquals("Administrator is not authorized to resource /hardtoken_functionality/edit_hardtoken_issuers. Msg: .", e.getMessage());
            }

        } finally {
            hardTokenSession.removeHardTokenIssuer(internalAdmin, alias);
            super.tearDownRemoveRole();
        }
    }
    
    @Test
    public void testIsAuthorizedToHardTokenIssuerWithoutBeingMemberOfRole() throws Exception {
        final String rolename = "testGetAuthorizedToHardTokenIssuer";
        final String issuerDn = "CN="+rolename;
        final TestX509CertificateAuthenticationToken admin = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(issuerDn, null, rolename,
                Arrays.asList(AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS), null);
        final String anotherRolename = "AnotherRoleName";
        final String anotherIssuerDn = "CN="+anotherRolename;
        final TestX509CertificateAuthenticationToken admin2 = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(anotherIssuerDn, null, anotherRolename,
                Arrays.asList(AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS), null);
        final String alias = "spacemonkeys";
        try {
            final Role anotherRole = roleSession.getRole(internalAdmin, null, anotherRolename);
            HardTokenIssuer hardTokenIssuer = new HardTokenIssuer();
            hardTokenIssuer.setDescription(alias);
            if (!hardTokenSession.addHardTokenIssuer(internalAdmin, alias, anotherRole.getRoleId(), hardTokenIssuer)) {
                fail("Could not add hard token issuer, test can not continue");
            }
            assertFalse(hardTokenSession.isAuthorizedToHardTokenIssuer(admin, alias));
        } finally {
            hardTokenSession.removeHardTokenIssuer(internalAdmin, alias);
            roleInitializationSession.removeAllAuthenticationTokensRoles(admin2);
            roleInitializationSession.removeAllAuthenticationTokensRoles(admin);
        }
    }
}
