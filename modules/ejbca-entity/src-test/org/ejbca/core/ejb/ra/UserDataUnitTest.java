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
package org.ejbca.core.ejb.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.NoSuchAlgorithmException;

import org.junit.Test;


/** 
 * Tests JUnit testable things from UserData entity bean.
 *
 */
public class UserDataUnitTest {

	@Test
    public void testUserPassword() throws NoSuchAlgorithmException {
    	UserData data = new UserData();
    	data.setPassword("foo123");
    	String hash = data.getPasswordHash();
    	// Check that it by default generates a strong bcrypt password hash
    	assertTrue(hash.startsWith("$2"));
    	assertFalse(data.comparePassword("bar123"));
    	assertTrue(data.comparePassword("foo123"));
    	// Set the same password again, it should be another hash this time
    	data.setPassword("foo123");
    	String hash1 = data.getPasswordHash();
    	assertTrue(hash1.startsWith("$2"));
    	assertFalse(hash1.equals(hash));
    }
	
	@Test
	public void testClearTextPassword() throws NoSuchAlgorithmException {
	    // Check that set clear text password works as well
	    UserData data = new UserData();
        data.setOpenPassword("primekey");
        String hash = data.getPasswordHash();
        // Check that it by default generates a strong bcrypt password hash
        assertTrue(hash.startsWith("$2"));
        assertFalse(data.comparePassword("foo123123"));
        assertTrue(data.comparePassword("primekey"));
        assertEquals("OBF:1z7a1vnw1v251uo71unr1v291vn61z7s", data.getClearPassword());
        assertEquals("primekey", data.getOpenPassword());
	}

}
