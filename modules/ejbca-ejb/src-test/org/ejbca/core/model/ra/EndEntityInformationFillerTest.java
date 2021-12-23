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
        profile.setValue(DnComponents.COUNTRY, 0, "FR");
        profile.setValue(DnComponents.ORGANIZATION, 0, "linagora");
        profile.setCabfOrganizationIdentifierUsed(true);
        profile.setCabfOrganizationIdentifier("VATSE-556677123401");
    }

    /**
     * Test merging of DNs with multiple components
     */
	@Test
    public void testMergeDN() {
	    EndEntityProfile p = new EndEntityProfile();
        p.addField(DnComponents.COMMONNAME);//5
        p.addField(DnComponents.ORGANIZATIONALUNIT);//11
        p.addField(DnComponents.ORGANIZATIONALUNIT);
        p.addField(DnComponents.ORGANIZATIONALUNIT);
        p.addField(DnComponents.COUNTRY);//16
        p.addField(DnComponents.ORGANIZATION);//12
        p.addField(DnComponents.ORGANIZATION);
        p.setValue(DnComponents.COMMONNAME, 0, "User Usersson");
        p.setValue(DnComponents.ORGANIZATIONALUNIT, 0, "Unit1");
        p.setValue(DnComponents.ORGANIZATIONALUNIT, 1, "Unit2");
        p.setValue(DnComponents.ORGANIZATIONALUNIT, 2, "Unit3");
        p.setValue(DnComponents.COUNTRY, 0, "SE");
        p.setValue(DnComponents.ORGANIZATION, 0, "Org1");
                
        EndEntityInformation user = new EndEntityInformation();
        // No DN in end entity to start with
    	EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());
        // Null should be the same as empty to start with
        user.setDN(null);
        user.setProfileMerged(false);
        
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());
        // or empty string
        user.setDN("");
        user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());
        
        user.setDN("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE");
        user.setProfileMerged(false);
        // Run it again, now everything is the same as default, and should turn out the same again
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // and again...
        user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // Set a simple DN, only CN, same as default
    	user.setDN("CN=User Usersson");
    	user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // Change to something else than default, this should override the default
        user.setDN("CN=Name2");
        user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // Change default
        p.setValue(DnComponents.COMMONNAME, 0, "Name2");
        user.setDN("CN=Name2");
        user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // Add some new fields
        user.setDN("CN=Name2,O=MyOrg");
        user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,OU=Unit1,OU=Unit2,OU=Unit3,O=MyOrg,C=SE", user.getDN());

        // Add some new fields in the DN, will be placed in the front as default values are "merged" in after
        // the first "default" value in the profile, will instead use the field from user, and the default values merged in where 
        // such items are missing from the user DN
        user.setDN("CN=Name2,O=MyOrg,OU=MyOrgU");
        user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,OU=MyOrgU,OU=Unit2,OU=Unit3,O=MyOrg,C=SE", user.getDN());

        // Change order in request
        user.setDN("O=MyOrg,OU=MyOrgU,CN=Name2");
        user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,OU=MyOrgU,OU=Unit2,OU=Unit3,O=MyOrg,C=SE", user.getDN());

        // Change order in request, and some values
        user.setDN("C=NO,O=MyOrg,OU=MyOrgU,CN=Name3");
        user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name3,OU=MyOrgU,OU=Unit2,OU=Unit3,O=MyOrg,C=NO", user.getDN());

        // Remove the last (third) OU, we should now override the second
        p.setValue(DnComponents.ORGANIZATIONALUNIT, 2, null);
        user.setDN("C=NO,O=MyOrg,OU=MyOrgU,CN=Name3");
        user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name3,OU=MyOrgU,OU=Unit2,O=MyOrg,C=NO", user.getDN());

        // Trim it down a little again
        user.setDN("CN=Name3,OU=MyOrgU");
        user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name3,OU=MyOrgU,OU=Unit2,O=Org1,C=SE", user.getDN());

        // Try the same again, just to be sure
        user.setDN("CN=Name3,OU=MyOrgU");
        user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name3,OU=MyOrgU,OU=Unit2,O=Org1,C=SE", user.getDN());

        // Add serialnumber
        user.setDN("SERIALNUMBER=123456789,OU=MyOrgU");
        user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,SN=123456789,OU=MyOrgU,OU=Unit2,O=Org1,C=SE", user.getDN());

        // Add serial number
        user.setDN("SERIALNUMBER=12345,OU=MyOrgU");
        user.setProfileMerged(false);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,SN=12345,OU=MyOrgU,OU=Unit2,O=Org1,C=SE", user.getDN());
        
        // Add serial number, and remove CN
        // This is the case where things get confused, because serial number makes CertTools.stringToBCDNString think that the DN is reversed 
        // making the OUs re-ordered.
        user.setDN("SERIALNUMBER=12345,OU=MyOrgU");
        user.setProfileMerged(false);
        p.setValue(DnComponents.COMMONNAME, 0, null);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("SN=12345,OU=Unit2,OU=MyOrgU,O=Org1,C=SE", user.getDN());
	}

    /**
     * Test merging of altNames with multiple components
     */
    @Test
    public void testMergeAltName() {
        //TODO
        // Order changed when I did the "fix"
        // assertEquals("rfc822Name=foo@bar.com,dnsName=foo.bar.com,dnsName=foo1.bar.com", data.getSubjectAltName());
        // ->dnsName=foo1.bar.com,dnsName=foo.bar.com,rfc822Name=foo@bar.com
    }
    
    /**
     * Test that DN is merged with a simple default value (O is not replaced, C is added), 
     * as well as CabfOrganizationIdentifier merged in (ExtendedInformation)
     */
    @Test
    public void testFillUserDataWithDefaultValuesDnOnly() {
        userData.setSendNotification(true);
        userData.setPassword("userPassword");
        String expectedUserDn="CN=userName,O=linagora,C=FR";
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
