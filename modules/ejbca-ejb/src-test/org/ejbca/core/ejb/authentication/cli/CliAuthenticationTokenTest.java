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
package org.ejbca.core.ejb.authentication.cli;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.user.AccessUserAspect;
import org.easymock.EasyMock;
import org.ejbca.util.crypto.SupportedPasswordHashAlgorithm;
import org.junit.Test;

/**
 * Unit tests for the CliAuthenticationToken class
 * 
 * @version $Id$
 * 
 */
public class CliAuthenticationTokenTest {

    private static final String BCRYPT_SALT = "$2a$01$Hja7ojbew3RWKA5d4AXMt.";
    
    /**
     * Make sure that each token is single-use only. This test tests both CliAuthenticationToken and the CliAuthenticationTokenRegistry
     * @throws AuthenticationFailedException 
     */
    @Test
    public void testUseTokenWorksTwiceInternally() throws AuthenticationFailedException {
        final Long referenceNumber = 0L;
        final String passwordHash = "kittens";
        CliAuthenticationToken authenticationToken = new CliAuthenticationToken(new UsernamePrincipal("TEST"), passwordHash, BCRYPT_SALT, referenceNumber,
                SupportedPasswordHashAlgorithm.SHA1_OLD);
        CliAuthenticationTokenReferenceRegistry.INSTANCE.registerToken(authenticationToken);
        AccessUserAspect accessUser = EasyMock.createMock(AccessUserAspect.class);
        EasyMock.expect(accessUser.getMatchValue()).andReturn("TEST");
        EasyMock.expect(accessUser.getTokenType()).andReturn(CliAuthenticationToken.TOKEN_TYPE);
        EasyMock.replay(accessUser);
        assertTrue(authenticationToken.matches(accessUser));
        // The token should still work
        assertTrue(authenticationToken.matches(accessUser));

        EasyMock.verify(accessUser);
    }
    @Test
    public void testUseTokenDoesNotWorkAfterSerialization() throws IOException, ClassNotFoundException, AuthenticationFailedException {
        final Long referenceNumber = 0L;
        final String passwordHash = "kittens";
        CliAuthenticationToken authenticationToken = new CliAuthenticationToken(new UsernamePrincipal("TEST"), passwordHash, BCRYPT_SALT, referenceNumber,
                SupportedPasswordHashAlgorithm.SHA1_OLD);
        CliAuthenticationTokenReferenceRegistry.INSTANCE.registerToken(authenticationToken);
        AccessUserAspect accessUser = EasyMock.createMock(AccessUserAspect.class);
        EasyMock.expect(accessUser.getTokenType()).andReturn(CliAuthenticationToken.TOKEN_TYPE).times(2);
        EasyMock.expect(accessUser.getMatchValue()).andReturn("TEST").times(2);
        EasyMock.replay(accessUser);
        assertTrue(authenticationToken.matches(accessUser));
        // Serialize the token and pick it up again.
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(byteArrayOutputStream);
        out.writeObject(authenticationToken);
        out.close();
        byte[] serializedObject = byteArrayOutputStream.toByteArray();

        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(serializedObject));
        CliAuthenticationToken deserializedObject = (CliAuthenticationToken) in.readObject();
        in.close();

        // The token should be spent now.
        try {
            deserializedObject.matches(accessUser);
            fail("CliAuthenticationFailedException should have been thrown");
        } catch (AuthenticationFailedException e) {
            //NOPMD
        }

        EasyMock.verify(accessUser);
    }

    @Test
    public void testReplayAttack() throws AuthenticationFailedException, SecurityException, NoSuchFieldException, IllegalArgumentException, IllegalAccessException  {
        final Long referenceNumber = 0L;
        final String passwordHash = "kittens";
        CliAuthenticationToken authenticationToken = new CliAuthenticationToken(new UsernamePrincipal("TEST"), passwordHash, BCRYPT_SALT, referenceNumber,
                SupportedPasswordHashAlgorithm.SHA1_OLD);
        CliAuthenticationTokenReferenceRegistry.INSTANCE.registerToken(authenticationToken);
        AccessUserAspect accessUser = EasyMock.createMock(AccessUserAspect.class);
        EasyMock.expect(accessUser.getMatchValue()).andReturn("TEST").times(2);
        EasyMock.expect(accessUser.getTokenType()).andReturn(CliAuthenticationToken.TOKEN_TYPE).times(2);
        EasyMock.replay(accessUser);
        assertTrue(authenticationToken.matches(accessUser));        
        // Modify the token, so that it becomes "spent"
        Field f = CliAuthenticationToken.class.getDeclaredField("isVerified");
        f.setAccessible(true);
        f.setBoolean(authenticationToken, false);
        boolean caught = false;
        try {
            authenticationToken.matches(accessUser);
        } catch (AuthenticationFailedException e) {
            caught = true;
        }
        assertTrue("Authentication failure did not occur for replay attack.", caught);
        EasyMock.verify(accessUser);
    }
    
    @Test 
    public void testIncorrectPasswordBehaviour() throws Exception {
        final Long referenceNumber = 0L;
        final String passwordHash = "kittens";
        CliAuthenticationToken authenticationToken = new CliAuthenticationToken(new UsernamePrincipal("TEST"), passwordHash, BCRYPT_SALT, referenceNumber,
                SupportedPasswordHashAlgorithm.SHA1_OLD);
        CliAuthenticationTokenReferenceRegistry.INSTANCE.registerToken(authenticationToken);
        AccessUserAspect accessUser = EasyMock.createMock(AccessUserAspect.class);
        EasyMock.expect(accessUser.getMatchValue()).andReturn("TEST");
        EasyMock.expect(accessUser.getTokenType()).andReturn(CliAuthenticationToken.TOKEN_TYPE);
        EasyMock.replay(accessUser);
        authenticationToken.setSha1Hash("You're a kitty!");
        boolean caught = false;
        try {
            authenticationToken.matches(accessUser);  
        } catch(AuthenticationFailedException e) {
            caught = true;
        }
        assertTrue("Authentication failure did not occur for incorrectly set password.", caught);
        
        EasyMock.verify(accessUser);
    }
    
    
}
