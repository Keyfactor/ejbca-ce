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
package org.cesecore.authorization.access;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.roles.RoleData;
import org.cesecore.util.Tuplet;
import org.easymock.EasyMock;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for the AccessTreeNode class.
 * 
 * Based on cesecore version:
 *      AccessTreeNodeTest.java 168 2011-01-27 10:07:30Z mikek
 * 
 * @version $Id$
 * 
 */
public class AccessTreeNodeTest {

    private AccessTreeNode rootNode;

    @Before
    public void setUp() {
        // Create the root Node.
        rootNode = new AccessTreeNode("/");
    }

    @After
    public void tearDown() {
        rootNode = null;
    }

    /**
     * This method should add a new access rule to root node.
     * 
     * @throws NoSuchFieldException
     * @throws SecurityException
     * @throws IllegalAccessException
     * @throws IllegalArgumentException
     */
    @Test
    public void testAddAccessRuleToRootNode() throws SecurityException, NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        AccessRuleData accessRule = EasyMock.createMock(AccessRuleData.class);
        RoleData role = EasyMock.createMock(RoleData.class);

        rootNode.addAccessRule("/", accessRule, role);

        // Use reflection to check that the AccessRule has been added.
        Field roleRulePairsField = rootNode.getClass().getDeclaredField("roleRulePairs");
        roleRulePairsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<Tuplet<RoleData, AccessRuleData>> roleRulePairs = (List<Tuplet<RoleData, AccessRuleData>>) roleRulePairsField.get(rootNode);
        Assert.assertFalse("No rule was added to root node", roleRulePairs.size() < 1);
        Assert.assertFalse("More than one rule was added to root node", roleRulePairs.size() > 1);
        Tuplet<RoleData, AccessRuleData> roleRulePair = roleRulePairs.get(0);
        Assert.assertEquals("Correct role was not added.", role, roleRulePair.getFirstElement());
        Assert.assertEquals("Correct rule was not added.", accessRule, roleRulePair.getSecondElement());
    }

    /**
     * Several tests are added to this method, since they're largely sequential.
     * 
     * @throws NoSuchFieldException
     * @throws SecurityException
     * @throws IllegalAccessException
     * @throws IllegalArgumentException
     */
    @Test
    public void testAddAccessRuleToChildren() throws SecurityException, NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        final String resource1 = "resource1";
        final String resource2 = "resource2";
        AccessRuleData accessRule_alpha = EasyMock.createMock(AccessRuleData.class);
        RoleData role_alpha = EasyMock.createMock(RoleData.class);

        rootNode.addAccessRule("/" + resource1, accessRule_alpha, role_alpha);

        Field childLeafsField = rootNode.getClass().getDeclaredField("leafs");
        childLeafsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        HashMap<String, AccessTreeNode> childLeafs = (HashMap<String, AccessTreeNode>) childLeafsField.get(rootNode);
        AccessTreeNode childNode = childLeafs.get(resource1);
        assertEquals(childNode.getResource(), resource1);

        rootNode.addAccessRule("/" + resource1 + "/" + resource2, accessRule_alpha, role_alpha);

        Field grandChildLeafsField = childNode.getClass().getDeclaredField("leafs");
        grandChildLeafsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        HashMap<String, AccessTreeNode> grandChildLeafs = (HashMap<String, AccessTreeNode>) grandChildLeafsField.get(childNode);
        AccessTreeNode grandChildNode = grandChildLeafs.get(resource2);
        assertEquals(grandChildNode.getResource(), resource2);
    }

    /**
     * Vanilla test, access to root.
     */
    @Test
    public void testIsAuthorizedToRoot() {
        AccessRuleData acceptRule = EasyMock.createMock(AccessRuleData.class);
        EasyMock.expect(acceptRule.getAccessRuleName()).andReturn("/").anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(acceptRule.getTreeState()).andReturn(AccessTreeState.STATE_ACCEPT);

        AccessUserAspectData accessUser = EasyMock.createMock(AccessUserAspectData.class);

        AuthenticationToken authenticationToken = EasyMock.createMock(AuthenticationToken.class);
        EasyMock.expect(authenticationToken.matches(accessUser)).andReturn(true);
        EasyMock.expect(authenticationToken.getDefaultMatchValue()).andReturn(X500PrincipalAccessMatchValue.NONE);
        EasyMock.expect(authenticationToken.matchTokenType(X509CertificateAuthenticationToken.TOKEN_TYPE)).andReturn(true);
        EasyMock.expect(authenticationToken.getMatchValueFromDatabaseValue(X500PrincipalAccessMatchValue.WITH_COUNTRY.getNumericValue())).andReturn(X500PrincipalAccessMatchValue.WITH_COUNTRY).anyTimes();
        EasyMock.expect(accessUser.getTokenType()).andReturn(X509CertificateAuthenticationToken.TOKEN_TYPE);
        EasyMock.expect(accessUser.getMatchWith()).andReturn(X500PrincipalAccessMatchValue.WITH_COUNTRY.getNumericValue()).anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(accessUser.getMatchTypeAsType()).andReturn(AccessMatchType.TYPE_EQUALCASE).anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(accessUser.getMatchValue()).andReturn("SE").anyTimes();	// Required if we run the test in trace mode

        Map<Integer, AccessUserAspectData> accessUsers = new HashMap<Integer, AccessUserAspectData>();
        final Integer accessUserPrimaryKey = 0;
        accessUsers.put(accessUserPrimaryKey, accessUser);

        RoleData role = EasyMock.createMock(RoleData.class);
        EasyMock.expect(role.getAccessUsers()).andReturn(accessUsers);

        EasyMock.replay(authenticationToken, acceptRule, role, accessUser);

        rootNode.addAccessRule("/", acceptRule, role);

        assertTrue(rootNode.isAuthorized(authenticationToken, "/"));

        EasyMock.verify(authenticationToken, acceptRule, role, accessUser);
    }

    /**
     * Now, let's add another rule for the same role with higher priority, and...decline <insert evil laugh>.
     */
    @Test
    public void testIsAuthorizedToRootWithHigherRankingUserDenial() {

        AccessRuleData acceptRule = EasyMock.createMock(AccessRuleData.class);
        EasyMock.expect(acceptRule.getAccessRuleName()).andReturn("/").anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(acceptRule.getTreeState()).andReturn(AccessTreeState.STATE_ACCEPT);
        AccessRuleData declineRule = EasyMock.createMock(AccessRuleData.class);
        EasyMock.expect(declineRule.getAccessRuleName()).andReturn("/").anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(declineRule.getTreeState()).andReturn(AccessTreeState.STATE_DECLINE);

        AccessUserAspectData countryUser = EasyMock.createMock(AccessUserAspectData.class);
        final Integer countryPrimaryKey = 0;
        AccessUserAspectData upnUser = EasyMock.createMock(AccessUserAspectData.class);

        Map<Integer, AccessUserAspectData> countryUsers = new HashMap<Integer, AccessUserAspectData>();
        countryUsers.put(countryPrimaryKey, countryUser);
        Map<Integer, AccessUserAspectData> upnUsers = new HashMap<Integer, AccessUserAspectData>();
        final Integer upnPrimaryKey = 1;
        upnUsers.put(upnPrimaryKey, upnUser);

        AuthenticationToken authenticationToken = EasyMock.createMock(AuthenticationToken.class);
        EasyMock.expect(authenticationToken.matches(countryUser)).andReturn(true);
        EasyMock.expect(authenticationToken.matches(upnUser)).andReturn(true);
        EasyMock.expect(authenticationToken.getDefaultMatchValue()).andReturn(X500PrincipalAccessMatchValue.NONE);
        EasyMock.expect(authenticationToken.matchTokenType(X509CertificateAuthenticationToken.TOKEN_TYPE)).andReturn(true).anyTimes();
        EasyMock.expect(authenticationToken.getMatchValueFromDatabaseValue(X500PrincipalAccessMatchValue.WITH_COUNTRY.getNumericValue())).andReturn(X500PrincipalAccessMatchValue.WITH_COUNTRY).anyTimes();
        EasyMock.expect(authenticationToken.getMatchValueFromDatabaseValue(X500PrincipalAccessMatchValue.WITH_UPN.getNumericValue())).andReturn(X500PrincipalAccessMatchValue.WITH_UPN).anyTimes();
        
        EasyMock.expect(countryUser.getMatchWith()).andReturn(X500PrincipalAccessMatchValue.WITH_COUNTRY.getNumericValue()).anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(countryUser.getMatchTypeAsType()).andReturn(AccessMatchType.TYPE_EQUALCASE).anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(countryUser.getMatchValue()).andReturn("SE").anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(countryUser.getTokenType()).andReturn(X509CertificateAuthenticationToken.TOKEN_TYPE);
        EasyMock.expect(upnUser.getMatchWith()).andReturn(X500PrincipalAccessMatchValue.WITH_UPN.getNumericValue()).anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(upnUser.getMatchTypeAsType()).andReturn(AccessMatchType.TYPE_EQUALCASE).anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(upnUser.getMatchValue()).andReturn("userid").anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(upnUser.getTokenType()).andReturn(X509CertificateAuthenticationToken.TOKEN_TYPE);

        RoleData role = EasyMock.createMock(RoleData.class);
        EasyMock.expect(role.getAccessUsers()).andReturn(countryUsers);
        EasyMock.expect(role.getAccessUsers()).andReturn(upnUsers);

        EasyMock.replay(acceptRule, declineRule, countryUser, upnUser, authenticationToken, role);

        rootNode.addAccessRule("/", acceptRule, role);
        rootNode.addAccessRule("/", declineRule, role);

        assertFalse(rootNode.isAuthorized(authenticationToken, "/"));

        EasyMock.verify(acceptRule, declineRule, upnUser, countryUser, authenticationToken, role);
    }

    /**
     * Test for nonexistent resource without having encountered a ACCEPT_RECURSIVE.
     */
    @Test
    public void testIsAuthorizedForNonExistentResourceNotRecursive() {
        final String resourcePath = "/parent/child";
        AuthenticationToken authenticationToken = EasyMock.createMock(AuthenticationToken.class);
        EasyMock.expect(authenticationToken.getDefaultMatchValue()).andReturn(X500PrincipalAccessMatchValue.NONE);
        EasyMock.replay(authenticationToken);
        assertFalse(rootNode.isAuthorized(authenticationToken, resourcePath));
        EasyMock.verify(authenticationToken);
    }

    /**
     * Now let's do the same with a child, adding ACCEPT_RECURSIVE to the root
     */
    @Test
    public void testIsAuthorizedForNonExistentResourceRecursive() {
        final String resourcePath = "/parent/child";

        AccessRuleData accessRule = EasyMock.createMock(AccessRuleData.class);
        EasyMock.expect(accessRule.getAccessRuleName()).andReturn("/").anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(accessRule.getTreeState()).andReturn(AccessTreeState.STATE_ACCEPT_RECURSIVE);

        AccessUserAspectData accessUser = EasyMock.createMock(AccessUserAspectData.class);
        EasyMock.expect(accessUser.getMatchWith()).andReturn(X500PrincipalAccessMatchValue.WITH_COUNTRY.getNumericValue()).anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(accessUser.getMatchTypeAsType()).andReturn(AccessMatchType.TYPE_EQUALCASE).anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(accessUser.getMatchValue()).andReturn("SE").anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(accessUser.getTokenType()).andReturn(X509CertificateAuthenticationToken.TOKEN_TYPE);

        AuthenticationToken authenticationToken = EasyMock.createMock(AuthenticationToken.class);
        EasyMock.expect(authenticationToken.matchTokenType(X509CertificateAuthenticationToken.TOKEN_TYPE)).andReturn(true);
        EasyMock.expect(authenticationToken.matches(accessUser)).andReturn(true);
        EasyMock.expect(authenticationToken.getDefaultMatchValue()).andReturn(X500PrincipalAccessMatchValue.NONE);
        EasyMock.expect(authenticationToken.getMatchValueFromDatabaseValue(X500PrincipalAccessMatchValue.WITH_COUNTRY.getNumericValue())).andReturn(X500PrincipalAccessMatchValue.WITH_COUNTRY).anyTimes();
        
        Map<Integer, AccessUserAspectData> accessUsers = new HashMap<Integer, AccessUserAspectData>();
        final Integer accessUserPrimaryKey = 0;
        accessUsers.put(accessUserPrimaryKey, accessUser);

        RoleData role = EasyMock.createMock(RoleData.class);
        EasyMock.expect(role.getAccessUsers()).andReturn(accessUsers);

        EasyMock.replay(authenticationToken, role, accessRule, accessUser);

        rootNode.addAccessRule("/", accessRule, role);

        // Having encountered an ACCEPT_RECURSIVE, we should return true even if the path doesn't exist.
        assertTrue(rootNode.isAuthorized(authenticationToken, resourcePath));

        EasyMock.verify(authenticationToken, role, accessRule);
    }

    /**
     * Basically a vanilla test.
     */
    @Test
    public void testIsAuthorizedForExistingChild() {

        AccessRuleData acceptRecursive = EasyMock.createMock(AccessRuleData.class);
        EasyMock.expect(acceptRecursive.getAccessRuleName()).andReturn("/").anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(acceptRecursive.getTreeState()).andReturn(AccessTreeState.STATE_ACCEPT_RECURSIVE);
        AccessRuleData unknown = EasyMock.createMock(AccessRuleData.class);
        EasyMock.expect(unknown.getAccessRuleName()).andReturn("/parent").anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(unknown.getTreeState()).andReturn(AccessTreeState.STATE_UNKNOWN);

        AccessUserAspectData accessUser = EasyMock.createMock(AccessUserAspectData.class);
        EasyMock.expect(accessUser.getMatchWith()).andReturn(X500PrincipalAccessMatchValue.WITH_COUNTRY.getNumericValue()).anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(accessUser.getMatchTypeAsType()).andReturn(AccessMatchType.TYPE_EQUALCASE).anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(accessUser.getMatchValue()).andReturn("SE").anyTimes();	// Required if we run the test in trace mode
        EasyMock.expect(accessUser.getTokenType()).andReturn(X509CertificateAuthenticationToken.TOKEN_TYPE).anyTimes(); // Required if we run the test in trace mode

        AuthenticationToken authenticationToken = EasyMock.createMock(AuthenticationToken.class);
        EasyMock.expect(authenticationToken.getDefaultMatchValue()).andReturn(X500PrincipalAccessMatchValue.NONE).times(2);
        EasyMock.expect(authenticationToken.matches(accessUser)).andReturn(true).times(2);
        EasyMock.expect(authenticationToken.matchTokenType(X509CertificateAuthenticationToken.TOKEN_TYPE)).andReturn(true).times(2);
        EasyMock.expect(authenticationToken.getMatchValueFromDatabaseValue(X500PrincipalAccessMatchValue.WITH_COUNTRY.getNumericValue())).andReturn(X500PrincipalAccessMatchValue.WITH_COUNTRY).anyTimes();

        Map<Integer, AccessUserAspectData> accessUsers = new HashMap<Integer, AccessUserAspectData>();
        final Integer accessUserPrimaryKey = 0;
        accessUsers.put(accessUserPrimaryKey, accessUser);

        RoleData role = EasyMock.createMock(RoleData.class);
        EasyMock.expect(role.getAccessUsers()).andReturn(accessUsers).times(2);

        EasyMock.replay(authenticationToken, role, acceptRecursive, unknown, accessUser);

        rootNode.addAccessRule("/", acceptRecursive, role);
        rootNode.addAccessRule("/parent", unknown, role);

        // Having encountered an ACCEPT_RECURSIVE, we should return true even if the path doesn't exist.
        assertTrue(rootNode.isAuthorized(authenticationToken, "/parent"));

        EasyMock.verify(authenticationToken, role, acceptRecursive, unknown, accessUser);
    }

}
