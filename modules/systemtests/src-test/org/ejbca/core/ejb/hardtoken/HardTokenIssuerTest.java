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

import java.util.ArrayList;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
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
public class HardTokenIssuerTest {
    private static Logger log = Logger.getLogger(HardTokenIssuerTest.class);
    
    private HardTokenSessionRemote hardTokenSession = EjbRemoteHelper.INSTANCE.getRemoteSession(HardTokenSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("HardTokenIssuerTest"));


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
        boolean ret = false;
        try {
            hardTokenSession.removeHardTokenIssuer(internalAdmin, "TEST");
            hardTokenSession.removeHardTokenIssuer(internalAdmin, "TEST2");
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing Certificate Profile failed", ret);
        log.trace("<test05removeHardTokenIssuers()");
    }

    @Test
    public void testIsAuthorizedToHardTokenIssuer() throws Exception {
        final TestX509CertificateAuthenticationToken admin = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider
                .authenticate(new AuthenticationSubject(null, null));

        final int caid = CertTools.getIssuerDN(admin.getCertificate()).hashCode();
        final String cN = CertTools.getPartFromDN(CertTools.getIssuerDN(admin.getCertificate()), "CN");
        final String rolename = "testGetAuthorizedToHardTokenIssuer";
        final String alias = "spacemonkeys";
        try {
            AdminGroupData role = roleManagementSession.create(internalAdmin, rolename);
            Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
            subjects.add(new AccessUserAspectData(rolename, caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, cN));
            role = roleManagementSession.addSubjectsToRole(internalAdmin, role, subjects);
            Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
            accessRules.add(new AccessRuleData(rolename, AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS, AccessRuleState.RULE_ACCEPT, false));
            role = roleManagementSession.addAccessRulesToRole(internalAdmin, role, accessRules);
            HardTokenIssuer issuer = new HardTokenIssuer();
            issuer.setDescription(alias);
            if (!hardTokenSession.addHardTokenIssuer(internalAdmin, alias, role.getPrimaryKey(), issuer)) {
                fail("Could not add hard token issuer, test can not continue");
            }
            assertTrue(hardTokenSession.isAuthorizedToHardTokenIssuer(admin, alias));
            
            // Test authorization to edit with an unauthorized admin
            try {
                hardTokenSession.addHardTokenIssuer(admin, alias, role.getPrimaryKey(), issuer);
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
            roleManagementSession.remove(internalAdmin, rolename);
        }
    }
    
    @Test
    public void testIsAuthorizedToHardTokenIssuerWithoutBeingMemberOfRole() throws Exception {
        final TestX509CertificateAuthenticationToken admin = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider
                .authenticate(new AuthenticationSubject(null, null));

        final int caid = CertTools.getIssuerDN(admin.getCertificate()).hashCode();
        final String cN = CertTools.getPartFromDN(CertTools.getIssuerDN(admin.getCertificate()), "CN");
        final String rolename = "testGetAuthorizedToHardTokenIssuer";
        final String anotherRolename = "AnotherRoleName";
        final String alias = "spacemonkeys";
        try {
            AdminGroupData role = roleManagementSession.create(internalAdmin, rolename);
            AdminGroupData anotherRole = roleManagementSession.create(internalAdmin, anotherRolename);
            Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
            subjects.add(new AccessUserAspectData(rolename, caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, cN));
            role = roleManagementSession.addSubjectsToRole(internalAdmin, role, subjects);
            Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
            accessRules.add(new AccessRuleData(rolename, AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS, AccessRuleState.RULE_ACCEPT, false));
            role = roleManagementSession.addAccessRulesToRole(internalAdmin, role, accessRules);
            anotherRole = roleManagementSession.addAccessRulesToRole(internalAdmin, anotherRole, accessRules);
            HardTokenIssuer issuer = new HardTokenIssuer();
            issuer.setDescription(alias);
            if (!hardTokenSession.addHardTokenIssuer(internalAdmin, alias, anotherRole.getPrimaryKey(), issuer)) {
                fail("Could not add hard token issuer, test can not continue");
            }
            assertFalse(hardTokenSession.isAuthorizedToHardTokenIssuer(admin, alias));
        } finally {
            hardTokenSession.removeHardTokenIssuer(internalAdmin, alias);
            roleManagementSession.remove(internalAdmin, rolename);
            roleManagementSession.remove(internalAdmin, anotherRolename);
        }
    }

}
