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

import java.util.Date;

import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.model.ra.UserDataVO;
import org.junit.Test;


/** Tests JUnit testable things from UserData entity bean.
*
* @version $Id$
*/
@SuppressWarnings("deprecation")
public class UserDataTest {

	@Test
    public void test01UserPassword() throws Exception {
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

    	// Now check that we can still use old password hashes transparently using the old fixed sha1 hash of foo123
    	data.setPasswordHash("3b303d8b0364d9265c06adc8584258376150c9b5");
    	assertEquals("3b303d8b0364d9265c06adc8584258376150c9b5", data.getPasswordHash());
    	assertFalse(data.comparePassword("bar123"));
    	assertTrue(data.comparePassword("foo123"));

    	// Check that set clear text password works as well
    	data.setOpenPassword("primekey");
    	hash = data.getPasswordHash();
    	// Check that it by default generates a strong bcrypt password hash
    	assertTrue(hash.startsWith("$2"));
    	assertFalse(data.comparePassword("foo123123"));
    	assertTrue(data.comparePassword("primekey"));
    	assertEquals("primekey", data.getClearPassword());

    }

    @Test
    public void test02UserDataVOToEndEntityInformation() throws Exception {
        UserDataVO data = new UserDataVO();
		data.setCAId(111);
		data.setDN("CN=wstest");
		data.setAdministrator(true);
		data.setCertificateProfileId(1);
		data.setEndEntityProfileId(1);
		data.setPassword("foo123");
		data.setStatus(10);
		Date now = new Date();
		data.setTimeCreated(now);
		data.setTimeModified(now);
		data.setTokenType(3);
		data.setType(new EndEntityType(EndEntityTypes.ENDUSER, EndEntityTypes.ADMINISTRATOR));
		data.setUsername("wstest");
		EndEntityInformation ei = data.toEndEntityInformation();
		assertEquals("wstest", ei.getUsername());
		assertEquals(111, ei.getCAId());
		assertEquals("CN=wstest", ei.getDN());
		assertEquals(true, ei.getAdministrator());
		assertEquals(1, ei.getCertificateProfileId());
		assertEquals(1, ei.getEndEntityProfileId());
		assertEquals("foo123", ei.getPassword());
		assertEquals(10, ei.getStatus());
		assertEquals(now, ei.getTimeCreated());
		assertEquals(now, ei.getTimeModified());
		assertEquals(3, ei.getTokenType());
		assertEquals(65, ei.getType().getHexValue());
	}
}
