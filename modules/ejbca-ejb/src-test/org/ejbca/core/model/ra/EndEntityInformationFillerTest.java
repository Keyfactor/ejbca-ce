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
package org.ejbca.core.model.ra;

import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/** Tests DN merging
 * 
 * @version $Id$
 */
public class EndEntityInformationFillerTest {
	EndEntityProfile profile;
	EndEntityInformation userData = new EndEntityInformation();

	@Before
    public void setUp() throws Exception {
        userData = new EndEntityInformation("userName", "CN=userName,O=linagora", -1688117755, "", "user@linagora.com", new EndEntityType(EndEntityTypes.ENDUSER), 3, 1, 2,
                new org.cesecore.certificates.endentity.ExtendedInformation());
        profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);//16
        profile.addField(DnComponents.ORGANIZATION);//12
        profile.setUsernameDefault("defaultUserName");
        profile.setPredefinedPassword("defaultPassword");
        profile.setClearTextPasswordDefault(true);
        profile.setKeyRecoverableDefault(false);
        profile.setSendNotificationDefault(false);
        profile.setEmailDomain("defaultMail@linagora.com");
        profile.setValue(DnComponents.COMMONNAME, 0, "defaultCN");
        profile.setValue(DnComponents.COUNTRY, 0, "fr");
        profile.setValue(DnComponents.ORGANIZATION, 0, "linagora");
        profile.setCabfOrganizationIdentifierUsed(true);
        profile.setCabfOrganizationIdentifier("VATSE-556677123401");
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
    	assertEquals("VATSE-556677123401", userData.getExtendedInformation().getCabfOrganizationIdentifier());
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
    	profile.setSendNotificationDefault(true);
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
    	profile.setEmailDomain("@linagora.com");
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

    @Test
    public void testNoCn(){
        String altName = EndEntityInformationFiller.copyDnsNameValueFromCn(profile, "");
        assertEquals("Alt name should be empty", "", altName);
    }

    @Test
    public void testOneDns(){
        profile.addField(DnComponents.DNSNAME);
        profile.setCopy(DnComponents.DNSNAME, 0, true);
        String altName = EndEntityInformationFiller.copyDnsNameValueFromCn(profile, "CN=commonName");
        assertEquals("Alt name should contain DNSNAME copied from CN", "DNSNAME=commonName", altName);
    }
}
