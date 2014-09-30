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
package org.ejbca.core.model.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.Before;
import org.junit.Test;

/** Tests DN merging
 * 
 * @version $Id$
 */
public class UserDataFillerTest {
	EndEntityProfile profile;
	EndEntityInformation userData = new EndEntityInformation();

	@Before
    public void setUp() throws Exception {
        userData = new EndEntityInformation("userName", "CN=userName,O=linagora", -1688117755, "", "user@linagora.com", new EndEntityType(EndEntityTypes.ENDUSER), 3, 1, 2, 0,
                new org.cesecore.certificates.endentity.ExtendedInformation());
        profile = new EndEntityProfile();
        profile.addField(EndEntityProfile.USERNAME);//0
        profile.addField(EndEntityProfile.PASSWORD);//1
        profile.addField(EndEntityProfile.CLEARTEXTPASSWORD);//2
        profile.addField(EndEntityProfile.KEYRECOVERABLE);//28
        profile.addField(EndEntityProfile.SENDNOTIFICATION);//35
        profile.addField(EndEntityProfile.EMAIL);//26
        profile.addField(DnComponents.COUNTRY);//16
        profile.addField(DnComponents.ORGANIZATION);//12
        profile.setValue(EndEntityProfile.USERNAME, 0, "defaultUserName");
        profile.setValue(EndEntityProfile.PASSWORD, 0, "defaultPassword");
        profile.setValue(EndEntityProfile.CLEARTEXTPASSWORD, 0, "true");
        profile.setValue(EndEntityProfile.KEYRECOVERABLE, 0, "false");
        profile.setValue(EndEntityProfile.SENDNOTIFICATION, 0, "false");
        profile.setValue(EndEntityProfile.EMAIL, 0, "defaultMail@linagora.com");
        profile.setValue(DnComponents.COMMONNAME, 0, "defaultCN");
        profile.setValue(DnComponents.COUNTRY, 0, "fr");
        profile.setValue(DnComponents.ORGANIZATION, 0, "linagora");
    }

    /**
     * Test dn is merged
     */
	@Test
    public void testFillUserDataWithDefaultValuesDnOnly() {
    	userData.setSendNotification(true);
    	userData.setPassword("userPassword");
    	String expectedUserDn="CN=userName,O=linagora,C=fr";
    	EndEntityInformationFiller.fillUserDataWithDefaultValues(userData, profile);
    	assertEquals("userName", userData.getUsername());
    	assertTrue(userData.getSendNotification());
    	assertEquals("user@linagora.com", userData.getEmail());
    	assertEquals("userPassword", userData.getPassword());
    	assertEquals(expectedUserDn, userData.getDN());
    }
    /**
     * userName is merged
     */
	@Test
    public void testFillUserDataWithDefaultValuesUserName() {
    	userData.setUsername("");
    	EndEntityInformationFiller.fillUserDataWithDefaultValues(userData, profile);
    	assertTrue(!userData.getUsername().equals("userName"));
    	assertEquals("defaultUserName", userData.getUsername());
    }
    /**
     * SendNotification is merged
     */
	@Test
   public void testFillUserDataWithDefaultValuesSendNotification() {
    	profile.setValue(EndEntityProfile.SENDNOTIFICATION, 0, "true");
    	EndEntityInformationFiller.fillUserDataWithDefaultValues(userData, profile);
    	assertTrue(userData.getSendNotification());
    }
    /**
     * Email is merged
     */
	@Test
    public void testFillUserDataWithDefaultValuesEmail() {
    	userData.setEmail("");
    	EndEntityInformationFiller.fillUserDataWithDefaultValues(userData, profile);
    	assertEquals("defaultMail@linagora.com", userData.getEmail());
    	userData.setEmail("");
    	//Email is not merged because profile's email is not a valid email
    	profile.setValue(EndEntityProfile.EMAIL, 0, "@linagora.com");
    	EndEntityInformationFiller.fillUserDataWithDefaultValues(userData, profile);
    	//@linagora.com is not a valid e-mail address, no merge
    	assertTrue(userData.getEmail().equals(""));
    	
    }
    /**
     * Password is merged
     */
	@Test
    public void testFillUserDataWithDefaultValuesPassword() {
    	EndEntityInformationFiller.fillUserDataWithDefaultValues(userData, profile);
    	assertEquals("defaultPassword", userData.getPassword());
    }
}
