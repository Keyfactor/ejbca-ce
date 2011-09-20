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
package org.cesecore.authentication;

import java.util.HashSet;
import java.util.Set;

import junit.framework.Assert;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderRemote;
import org.junit.Test;

/**
 * Test class for the AuthenticationSessionBean
 * 
 * Based on cesecore version:   
 *      AuthenticationSessionBeanTest.java 168 2011-01-27 10:07:30Z mikek
 * 
 * @version $Id$
 * 
 */
public class AuthenticationSessionBeanTest {

    private AuthenticationSessionRemote authentication = JndiHelper.getRemoteSession(AuthenticationSessionRemote.class);
    private SimpleAuthenticationProviderRemote authenticationProvider = JndiHelper.getRemoteSession(SimpleAuthenticationProviderRemote.class);
    
    /**
     * This test is mainly to test the theory that an EJB can be referenced via an interface.
     * 
     */
    @Test
    public void testBasicAuthentication() {
        SimpleSubject subject = new SimpleSubject(null, null);
        AuthenticationToken token = authentication.authenticate(subject, authenticationProvider);
        Assert.assertNotNull("Token was not succesfully delivered by trivial AuthenticationProvider implementation.", token);
    }

    @Test
    public void testAuthenticationFailure() {
    	// A credential "fail" will force failure in the SimpleAuthenticationProviderSessionBean
    	Set<String> set = new HashSet<String>();
    	set.add("fail");
        SimpleSubject subject = new SimpleSubject(null, set);
        AuthenticationToken token = authentication.authenticate(subject, authenticationProvider);
        Assert.assertNull("The authentication should have failed, because we added a 'fail' credential.", token);
    }

}
