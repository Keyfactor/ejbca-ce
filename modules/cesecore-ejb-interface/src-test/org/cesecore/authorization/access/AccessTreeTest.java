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

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collection;

import org.junit.Assert;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.roles.RoleData;
import org.easymock.EasyMock;
import org.junit.Test;

/**
 * JUnit tests of the AccessTree class.
 * 
 * @version $Id$
 * 
 */
public class AccessTreeTest {

    /**
     * Tests the buildTree method. In order to keep this method on unit level, only the root level node will be built. A proper is built in the
     * functional tests.
     * 
     * @throws NoSuchFieldException
     * @throws SecurityException
     * @throws IllegalAccessException
     * @throws IllegalArgumentException
     */
    @Test
    public void testBuildTree() throws SecurityException, NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        AccessTree accessTree = new AccessTree();
        Collection<RoleData> roles = new ArrayList<RoleData>();
        accessTree.buildTree(roles);

        // Extract the root node using reflection.
        Field rootNodeField = accessTree.getClass().getDeclaredField("rootNode");
        rootNodeField.setAccessible(true);
        AccessTreeNode rootNode = (AccessTreeNode) rootNodeField.get(accessTree);
        Assert.assertEquals("Root node was not created in AccessTree", "/", rootNode.getResource());
    }

    /**
     * The only logic in this method is that which adds a slash in front of a specified resources that requires one, so this is consequently all that
     * we'll test on this level.
     * 
     * No assert is required in this test, the actual test on the input parameter is performed by EasyMock.expect
     * 
     * @throws NoSuchFieldException 
     * @throws SecurityException 
     * @throws IllegalAccessException 
     * @throws IllegalArgumentException 
     * @throws AuthenticationFailedException 
     */
    @Test
    public void testIsAuthorizedHandlesResourcesWithoutSlash() throws SecurityException, NoSuchFieldException, IllegalArgumentException, IllegalAccessException, AuthenticationFailedException {        
        AuthenticationToken authenticationToken = EasyMock.createMock(AuthenticationToken.class);
        AccessTree accessTree = new AccessTree();
        AccessTreeNode rootNode = EasyMock.createMock(AccessTreeNode.class);
        EasyMock.expect(rootNode.isAuthorized(authenticationToken, "/fancypants", false)).andReturn(true);
        EasyMock.replay(rootNode);
        
        //Use reflection to inject our mocked rootNode.
        Field rootNodeField = accessTree.getClass().getDeclaredField("rootNode");
        rootNodeField.setAccessible(true);
        rootNodeField.set(accessTree, rootNode);    
        accessTree.isAuthorized(authenticationToken, "fancypants");
        EasyMock.verify(rootNode);
    }

}
