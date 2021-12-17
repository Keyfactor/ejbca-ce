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

import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


/** Tests DN merging
 * 
 * @version $Id$
 */
public class EndEntityInformationFillerTest {
	EndEntityProfile profile;
	EndEntityProfile bigProfile;
	String bigUserDn;
	EndEntityInformation userData = new EndEntityInformation();
    private static final Logger log = Logger.getLogger(EndEntityInformationFillerTest.class);


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
        testCreateBigProfile();
        testCreateBigUserDn();
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
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());
        // or empty string
        user.setDN("");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());
        
        // Run it again, now everything is the same as default, and should turn out the same again
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // and again...
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // Set a simple DN, only CN, same as default
    	user.setDN("CN=User Usersson");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // Change to something else than default, this should override the default
        user.setDN("CN=Name2");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // Change default
        p.setValue(DnComponents.COMMONNAME, 0, "Name2");
        user.setDN("CN=Name2");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // Add some new fields
        user.setDN("CN=Name2,O=MyOrg");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,OU=Unit1,OU=Unit2,OU=Unit3,O=MyOrg,C=SE", user.getDN());

        // Add some new fields in the DN, will be placed in the front as default values are "merged" in after
        // the first "default" value in the profile, will instead use the field from user, and the default values merged in where 
        // such items are missing from the user DN
        user.setDN("CN=Name2,O=MyOrg,OU=MyOrgU");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,OU=MyOrgU,OU=Unit2,OU=Unit3,O=MyOrg,C=SE", user.getDN());

        // Change order in request
        user.setDN("O=MyOrg,OU=MyOrgU,CN=Name2");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,OU=MyOrgU,OU=Unit2,OU=Unit3,O=MyOrg,C=SE", user.getDN());

        // Change order in request, and some values
        user.setDN("C=NO,O=MyOrg,OU=MyOrgU,CN=Name3");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name3,OU=MyOrgU,OU=Unit2,OU=Unit3,O=MyOrg,C=NO", user.getDN());

        // Remove the last (third) OU, we should now override the second
        p.setValue(DnComponents.ORGANIZATIONALUNIT, 2, null);
        user.setDN("C=NO,O=MyOrg,OU=MyOrgU,CN=Name3");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name3,OU=MyOrgU,OU=Unit2,O=MyOrg,C=NO", user.getDN());

        // Trim it down a little again
        user.setDN("CN=Name3,OU=MyOrgU");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name3,OU=MyOrgU,OU=Unit2,O=Org1,C=SE", user.getDN());

        // Try the same again, just to be sure
        user.setDN("CN=Name3,OU=MyOrgU");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name3,OU=MyOrgU,OU=Unit2,O=Org1,C=SE", user.getDN());

        // Add serialnumber
        user.setDN("SERIALNUMBER=123456789,OU=MyOrgU");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,SN=123456789,OU=MyOrgU,OU=Unit2,O=Org1,C=SE", user.getDN());

        // Add serial number
        user.setDN("SERIALNUMBER=12345,OU=MyOrgU");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,SN=12345,OU=MyOrgU,OU=Unit2,O=Org1,C=SE", user.getDN());
        
        // Add serial number, and remove CN
        // This is the case where things get confused, because serial number makes CertTools.stringToBCDNString think that the DN is reversed 
        // making the OUs re-ordered.
        user.setDN("SERIALNUMBER=12345,OU=MyOrgU");
        p.setValue(DnComponents.COMMONNAME, 0, null);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("SN=12345,OU=Unit2,OU=MyOrgU,O=Org1,C=SE", user.getDN());
	}
	
	/**
     * Test merging of DNs with multiple components
     */
    @Test
    public void testMergeDNStringNewFunction() {
        EndEntityProfile p = new EndEntityProfile();
        //p.addField(DnComponents.COMMONNAME); by  default an empty CN field is created
        p.addField(DnComponents.ORGANIZATIONALUNIT);//11
        p.addField(DnComponents.ORGANIZATIONALUNIT);
        p.addField(DnComponents.ORGANIZATIONALUNIT);
        p.addField(DnComponents.ORGANIZATION);//12
        p.addField(DnComponents.ORGANIZATION);        
        p.addField(DnComponents.COUNTRY);//16

        p.setValue(DnComponents.COMMONNAME, 0, "User Usersson");
        p.setValue(DnComponents.ORGANIZATIONALUNIT, 0, "Unit1");
        p.setValue(DnComponents.ORGANIZATIONALUNIT, 1, "Unit2");
        p.setValue(DnComponents.ORGANIZATIONALUNIT, 2, "Unit3");
        p.setValue(DnComponents.COUNTRY, 0, "SE");
        p.setValue(DnComponents.ORGANIZATION, 0, "Org1");
        
        EndEntityInformation user = new EndEntityInformation();
        // No DN in end entity to start with
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());
        // Null should be the same as empty to start with
        user.setDN(null);
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());
        // or empty string
        user.setDN("");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());
        
        // Run it again, now everything is the same as default, and should turn out the same again
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // and again...
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // Set a simple DN, only CN, same as default
        user.setDN("CN=User Usersson");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // Change to something else than default, this should override the default
        user.setDN("CN=Name2");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name2,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // Change default
        p.setValue(DnComponents.COMMONNAME, 0, "Name2");
        user.setDN("CN=Name2");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name2,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", user.getDN());

        // Add some new fields
        user.setDN("CN=Name20,O=MyOrg");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name20,OU=Unit1,OU=Unit2,OU=Unit3,O=MyOrg,O=Org1,C=SE", user.getDN());

        // Add some new fields in the DN, will be placed in the front as default values are "merged" in after
        // the first "default" value in the profile, will instead use the field from user, and the default values merged in where 
        // such items are missing from the user DN
        user.setDN("CN=Name2,O=MyOrg,OU=MyOrgU");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name2,OU=MyOrgU,OU=Unit2,OU=Unit3,O=MyOrg,O=Org1,C=SE", user.getDN());

        // Change order in request
        user.setDN("O=MyOrg,OU=MyOrgU,CN=Name2");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name2,OU=MyOrgU,OU=Unit2,OU=Unit3,O=MyOrg,O=Org1,C=SE", user.getDN());

        // Change order in request, and some values
        user.setDN("C=NO,O=MyOrg,OU=MyOrgU,CN=Name3");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name3,OU=MyOrgU,OU=Unit2,OU=Unit3,O=MyOrg,O=Org1,C=NO", user.getDN());

        // Remove the last (third) OU, we should now override the second
        p.setValue(DnComponents.ORGANIZATIONALUNIT, 2, null);
        user.setDN("C=NO,O=MyOrg,OU=MyOrgU,CN=Name3");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name3,OU=MyOrgU,OU=Unit1,OU=Unit2,O=MyOrg,O=Org1,C=NO", user.getDN());

        // Trim it down a little again
        user.setDN("CN=Name3,OU=MyOrgU");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name3,OU=MyOrgU,OU=Unit1,OU=Unit2,O=Org1,C=SE", user.getDN());

        // Try the same again, just to be sure
        p.removeField(DnComponents.ORGANIZATIONALUNIT, 0);
        user.setDN("CN=Name3,OU=MyOrgU");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name3,OU=MyOrgU,OU=Unit2,O=Org1,C=SE", user.getDN());

        // Add serialnumber
        p.addField(DnComponents.DNSERIALNUMBER);
        user.setDN("SN=123456789,OU=MyOrgU");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name2,OU=MyOrgU,OU=Unit2,O=Org1,C=SE,SN=123456789", user.getDN());

        // Add serial number
        user.setDN("SN=12345,OU=MyOrgU");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name2,OU=MyOrgU,OU=Unit2,O=Org1,C=SE,SN=12345", user.getDN());
        
        // Add serial number, and remove CN
        // This is the case where things get confused, because serial number makes CertTools.stringToBCDNString think that the DN is reversed 
        // making the OUs re-ordered.
        user.setDN("SN=12345,OU=MyOrgU");
        p.setValue(DnComponents.COMMONNAME, 0, null);
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("OU=MyOrgU,OU=Unit2,O=Org1,C=SE,SN=12345", user.getDN());
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
    
    private void testCreateBigProfile() {
        bigProfile = new EndEntityProfile();
        EndEntityProfile p = bigProfile;
        for(int i=0; i<100; i++) {
            p.addField(DnComponents.ORGANIZATIONALUNIT);
            if(i%2==0) {
                p.setValue(DnComponents.ORGANIZATIONALUNIT, i, "Unit"+i);   
            }
        }
        p.addField(DnComponents.COUNTRY);
        for(int i=0; i<150; i++) {
            p.addField(DnComponents.ORGANIZATION);
            if(i%3==0) {
                p.setValue(DnComponents.ORGANIZATION, i, "ORGANIZATION"+i);   
            }
        }
        p.addField(DnComponents.COUNTRY);
        p.setValue(DnComponents.COUNTRY, 0, "SE");
        p.setValue(DnComponents.COMMONNAME, 0, "User Usersson");
    }
    
    private void testCreateBigUserDn() {
        StringBuilder sb = new StringBuilder();
        sb.append("CN=Name2");
        for(int i=0; i<40; i++) {
            sb.append(",OU=MyOrgCustom"+i);
        }
        for(int i=0; i<65; i++) {
            sb.append(",O=OrgCustom"+i);
        }
    }
    
    private void testMergeDNNewPerf() {
        EndEntityInformation user = new EndEntityInformation();
        user.setDN(bigUserDn);
        EndEntityInformationFiller.mergeDnString(user, bigProfile);
    }
    
    private void testMergeDNOldPerf() {
        EndEntityInformation user = new EndEntityInformation();
        user.setDN(bigUserDn);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, bigProfile);
    }
    
    @Test
    public void testMergeDNNewMulti() {
        for(int i=0; i<1000; i++) {
            testMergeDNNewPerf();
        }
    }
    
    @Test
    public void testMergeDNOldMulti() {
        for(int i=0; i<1000; i++) {
            testMergeDNOldPerf();
        }
    }
    
    /**
     * Test merging of DNs with multiple components
     */
    @Test
    public void testMergeDNString() {
        EndEntityProfile p = new EndEntityProfile();
        //p.addField(DnComponents.COMMONNAME); by default a CN field is added by noarg constructor
        p.addField(DnComponents.ORGANIZATIONALUNIT);
        p.addField(DnComponents.ORGANIZATIONALUNIT);
        p.addField(DnComponents.ORGANIZATIONALUNIT);
        p.addField(DnComponents.ORGANIZATIONALUNIT);
        p.addField(DnComponents.ORGANIZATION);
        p.addField(DnComponents.ORGANIZATION);        
        p.addField(DnComponents.COUNTRY);
        p.addField(DnComponents.DNEMAILADDRESS);

        p.setValue(DnComponents.COMMONNAME, 0, "User Usersson");
        p.setValue(DnComponents.ORGANIZATIONALUNIT, 0, "Unit1");
        p.setValue(DnComponents.ORGANIZATIONALUNIT, 1, "Unit2");
        p.setValue(DnComponents.COUNTRY, 0, "SE");
        p.setValue(DnComponents.ORGANIZATION, 0, "Org1");
        
        EndEntityInformation user = new EndEntityInformation();
        user.setDN("CN=Name2,OU=MyOrg1,OU=MyOrg2");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name2,OU=MyOrg1,OU=MyOrg2,OU=Unit1,OU=Unit2,O=Org1,C=SE", user.getDN());
        
        user.setDN("CN=Name2,OU=MyOrg1,OU=MyOrg2");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2,OU=MyOrg1,OU=MyOrg2,O=Org1,C=SE", user.getDN());
        
        try {
            user.setDN("CN=Name2,OU=MyOrg1,OU=MyOrg2,OU=MyOrg3,OU=MyOrg4,OU=MyOrg5");
            EndEntityInformationFiller.mergeDnString(user, p);  
            fail("Processed user dn with too many of a dn type.");
        } catch (Exception e) {
            assertEquals("User DN has too many components for OU", e.getMessage());
        }
        
        try {
            user.setDN("CN=Name2,OU=MyOrg1,OU=,OU=MyOrg2");
            EndEntityInformationFiller.mergeDnString(user, p);  
            fail("Processed user dn with invalid user dn.");
        } catch (Exception e) {
            assertEquals("Invalid DN component: OU=", e.getMessage());
        }
        
        try {
            user.setDN("CN=Name2,OU=MyOrg1,OU=,OU=MyOrg2");
            EndEntityInformationFiller.mergeDnString(user, p);  
            fail("Processed user dn with invalid user dn.");
        } catch (Exception e) {
        }
        
        p.setModifyable(DnComponents.ORGANIZATIONALUNIT, 0, false);
        
        user.setDN("CN=Name2,OU=MyOrg1,OU=MyOrg2,OU=MyOrg3");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name2,OU=MyOrg1,OU=MyOrg2,OU=MyOrg3,OU=Unit1,O=Org1,C=SE", user.getDN());
    
        p.setModifyable(DnComponents.ORGANIZATIONALUNIT, 0, true);
        p.setModifyable(DnComponents.ORGANIZATIONALUNIT, 1, false);
        
        user = new EndEntityInformation();
        user.setDN("CN=Name2,OU=MyOrg1,OU=MyOrg2,OU=MyOrg3");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name2,OU=MyOrg1,OU=MyOrg2,OU=MyOrg3,OU=Unit2,O=Org1,C=SE", user.getDN());
    
        try {
            user.setDN("CN=Name2,OU=MyOrg1,OU=MyOrg2,OU=MyOrg3,OU=MyOrg4");
            EndEntityInformationFiller.mergeDnString(user, p);  
            fail("Processed user dn with too many of a dn type with non-modifable and nonempty dn.");
        } catch (Exception e) {
            assertEquals("User DN has too many components for OU", e.getMessage());
        }
    }
    
    
    @Test
    public void testMergeDNMultiValueRdn() {
        EndEntityProfile p = new EndEntityProfile();
        p.addField(DnComponents.ORGANIZATIONALUNIT);
        p.addField(DnComponents.ORGANIZATIONALUNIT);
        p.addField(DnComponents.ORGANIZATIONALUNIT);
        p.addField(DnComponents.ORGANIZATIONALUNIT);
        p.addField(DnComponents.ORGANIZATION);
        p.addField(DnComponents.ORGANIZATION);        
        p.addField(DnComponents.COUNTRY);

        p.setValue(DnComponents.COMMONNAME, 0, "User Usersson");
        p.setValue(DnComponents.ORGANIZATIONALUNIT, 0, "Unit1");
        p.setValue(DnComponents.ORGANIZATIONALUNIT, 1, "Unit2");
        p.setValue(DnComponents.COUNTRY, 0, "SE");
        p.setValue(DnComponents.ORGANIZATION, 0, "Org1");
        
        EndEntityInformation user = new EndEntityInformation();
        user.setDN("CN=Name2+OU=MyOrg1,OU=MyOrg2,OU=MyOrg3");
        EndEntityInformationFiller.mergeDnString(user, p);
        assertEquals("CN=Name2+OU=MyOrg1,OU=MyOrg2,OU=MyOrg3,OU=Unit2,O=Org1,C=SE", user.getDN());
        
        user.setDN("CN=Name2+OU=MyOrg1,OU=MyOrg2");
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals("CN=Name2+OU=MyOrg1,OU=MyOrg2,OU=Unit2,O=Org1,C=SE", user.getDN());
    
    }
    
    /**
     * Test merging of SANs with multiple components
     */
    @Test
    public void testMergeSanString() {
        EndEntityProfile p = new EndEntityProfile();
        p.addField(DnComponents.DNSNAME);
        p.addField(DnComponents.DNSNAME);
        p.addField(DnComponents.DNSNAME);
        p.addField(DnComponents.RFC822NAME);
        p.addField(DnComponents.RFC822NAME);
        p.addField(DnComponents.DNSNAME);
        p.setValue(DnComponents.DNSNAME, 2, "server.bad.com");
        p.setValue(DnComponents.DNSNAME, 3, "server.superbad.com");
        
        String san = "DNSNAME=foo.bar.com,DNSNAME=foo1.bar.com,RFC822NAME=foo@bar.com";
        EndEntityInformation user = new EndEntityInformation();
        user.setSubjectAltName(san);
        EndEntityInformationFiller.mergeSanString(user, p);
        assertEquals("DNSNAME=foo.bar.com,DNSNAME=foo1.bar.com,DNSNAME=server.bad.com,"
                + "DNSNAME=server.superbad.com,RFC822NAME=foo@bar.com", user.getSubjectAltName());
        
        user.setSubjectAltName(san);
        EndEntityInformationFiller.fillUserDataWithDefaultValues(user, p);
        assertEquals(san, user.getSubjectAltName());
    
    }
    
}
