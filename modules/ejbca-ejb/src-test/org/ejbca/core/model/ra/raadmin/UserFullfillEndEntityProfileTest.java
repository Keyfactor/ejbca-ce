/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.ra.raadmin;

import java.text.DateFormat;
import java.util.Date;
import java.util.Locale;

import junit.framework.TestCase;

import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.util.dn.DnComponents;



/**
 * Tests the end entity profile entity bean profile checks only
 *
 * @version $Id$
 */
public class UserFullfillEndEntityProfileTest extends TestCase {
    private static final Logger log = Logger.getLogger(UserFullfillEndEntityProfileTest.class);
    final private static String standardDN = "CN=John Smith,OU=DEP1_1,OU=DEP2_1,C=SE";
    

    /**
     * Creates a new TestEndEntityProfile object.
     *
     * @param name name
     */
    public UserFullfillEndEntityProfileTest(String name) {    	
        super(name);
    }

    public void setUp() throws Exception {
        log.trace(">setUp()");
        log.setLevel(Level.DEBUG);
        log.trace("<setUp()");
    }

    public void tearDown() throws Exception {
    }

    /**
     * Test the profile fulfilling rutines
     *
     * @throws Exception error
     */
    public void test01fulfillEndEntityProfiles() throws Exception {
        log.trace(">test01fulfillEndEntityProfiles()");
        // Dummy caids
        final int testca1 = 2;
        final int testca2 = 3;
        
        int currentSubTest = 1;
        {
        final EndEntityProfile profile = new EndEntityProfile();
        
        // Set so CN=modifyable required, OU0={DEP1_1,DEP1_2} required, OU1={DEP2_1,DEP2_2} required, C=OU1={SE,DK} not required 
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.COUNTRY);
        
        profile.setRequired(DnComponents.ORGANIZATIONUNIT,0,true);
        profile.setRequired(DnComponents.ORGANIZATIONUNIT,1,true);
        
        profile.setModifyable(DnComponents.ORGANIZATIONUNIT,0,false);
        profile.setModifyable(DnComponents.ORGANIZATIONUNIT,1,false);
        profile.setModifyable(DnComponents.COUNTRY,0,false);
        
        profile.setValue(DnComponents.ORGANIZATIONUNIT,0,"DEP1_1;DEP1_2");
        profile.setValue(DnComponents.ORGANIZATIONUNIT,1,"DEP2_1;DEP2_2");
        profile.setValue(DnComponents.COUNTRY,0,"SE;DK");
        
        profile.setValue(EndEntityProfile.AVAILCAS,0,""+testca1);
        
        // Test completly erronious DN
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","blabla","","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Profile does not check DN at all.", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + " = OK");
        }

        // Test correct DN
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN,"null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          log.debug("End Entity Profile Fulfill Test " + (currentSubTest++) + " " + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue(e.getMessage(), false);
        }
        
        // Test no username even though is required
        try{ 
          profile.doesUserFullfillEndEntityProfile("","password",standardDN,"null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("UserName is not checked even though it's required", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Profile Fulfill Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");	
        }
        
        // Test no password even though is required
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","",standardDN,"null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Password is not checked even though it's required", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Profile Test Fulfill " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test with no CN (required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","OU=DEP1_1,OU=DEP2_1,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Error Required CN field wasn't checked", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test with only one OU  (2 required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=DEP2_1,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Error Required OU field wasn't checked", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test were second OU have the wrong value (Dep2_1 or Dep2_2)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_3,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Error value of second OU field wasn't checked", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage()+ " = OK");
        }
        
        // Test without C (not required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_2","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){        	
        	assertTrue(e.getMessage(), false);
        }
        
        // Test illegal value of  C (SE or DK)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_2, C=NO","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Inproper check of C value.", false);
        }catch(UserDoesntFullfillEndEntityProfile e){        	        	
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Add some subject altname fields
        profile.addField(DnComponents.RFC822NAME);
        profile.addField(DnComponents.DNSNAME);
        profile.addField(DnComponents.UPN);
        profile.addField(DnComponents.IPADDRESS);
        
        profile.setRequired(DnComponents.RFC822NAME,0,true);
        profile.setRequired(DnComponents.DNSNAME,0,true);
        profile.setRequired(DnComponents.UPN,0,true);
        profile.setRequired(DnComponents.IPADDRESS,0,true);
                
        profile.setModifyable(DnComponents.RFC822NAME,0,false);
        profile.setModifyable(DnComponents.DNSNAME,0,false);
        profile.setModifyable(DnComponents.UPN,0,false);
        profile.setModifyable(DnComponents.IPADDRESS,0,true);
        
        
        profile.setValue(DnComponents.RFC822NAME,0,"test.com");
        profile.setValue(DnComponents.DNSNAME,0,"test.primekey.se");
        profile.setValue(DnComponents.UPN,0,"test.com;primekey.se");
        profile.setValue(DnComponents.IPADDRESS,0,"11.11.1.1");

        profile.setRequired(EndEntityProfile.EMAIL,0,true);
        profile.setModifyable(EndEntityProfile.EMAIL,0,false);
        profile.setValue(EndEntityProfile.EMAIL,0,"test.com;primekey.se");
        
        // Test completly erronious Alt Name
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN,"blabla","","test@test.com",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Profile does not check altname at all.", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + " = OK");
        }

        // Test correct Alt Name
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN,"RFC822NAME=test@test.com, dnsname=test.primekey.se, Upn=test@primekey.se, ipaddress=11.11.1.2","","test@test.com",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          log.debug("End Entity Profile Fulfill Test " + (currentSubTest++) + " " + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue(e.getMessage(), false);
        }
                
        
        // Test with no RFC822NAME (required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN,"dnsname=test.primekey.se, Upn=test@primekey.se, ipaddress=11.11.1.2","","test@test.com",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Error Required RFC822NAME field wasn't checked", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test with one RFC822NAME to many
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN, "rfc822name=test@test.com, rfc822name=test@primekey.se, dnsname=test.primekey.se, Upn=test@primekey.se, ipaddress=11.11.1.2","","test@test.com",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("To many RFC822 names fields wasn't checked", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test that only domain is checked for RFC822name and UPN
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN, "rfc822name=test@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
           log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + "  = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Not only domains of RFC822NAME and UPN where checked: " + e.getMessage() , false);        	
        }
        
        // Test were DNS have illegal value
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN,"rfc822name=test@test.com, dnsname=test2.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Error value of DNS not checked.", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage()+ " = OK");
        }
        
        // Test without IPADDRESS (required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN,"rfc822name=test@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Error not checking number of IPADDRESS properly.", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + " = OK");
        	
        }
        
        
        // Test without email field (required) 1
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN,"rfc822name=test@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.1","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Inproper check of email field.", false);
        }catch(UserDoesntFullfillEndEntityProfile e){        	        	
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test without email field (required) 2
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN,"rfc822name=test@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.1","","null",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Inproper check of email field.", false);
        }catch(UserDoesntFullfillEndEntityProfile e){        	        	
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test without email field (required) 3
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN,"rfc822name=test@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se,ipaddress=11.11.1.1","",null,SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Inproper check of email field.", false);
        }catch(UserDoesntFullfillEndEntityProfile e){        	        	
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test illegal value of  email field (test.com or primekey.se) 1
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN,"rfc822name=test11@test1.com, dnsname=test.primekey.se, Upn=test12@primekey.se,ipaddress=11.11.1.1","","test11@test1.com",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Inproper check of email field values.", false);
        }catch(UserDoesntFullfillEndEntityProfile e){        	        	
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES,0, SecConst.CERTPROFILE_FIXED_ENDUSER + ";" + SecConst.CERTPROFILE_FIXED_SUBCA);
        
        // Test illegal value of  Certificate Profile
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN,"rfc822name=test11@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se,ipaddress=11.11.1.1","","test11@test.com",SecConst.CERTPROFILE_FIXED_ROOTCA, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          assertTrue("Inproper check of certificate profile values.", false);
        }catch(UserDoesntFullfillEndEntityProfile e){        	        	
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test Wrong CA
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password",standardDN,"rfc822name=test11@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se,ipaddress=11.11.1.1","","test11@test.com",SecConst.CERTPROFILE_FIXED_SUBCA, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca2, null);
          assertTrue("Inproper check of available ca's.", false);
        }catch(UserDoesntFullfillEndEntityProfile e){        	        	
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test with a mix of several rfc822name fields
        //profile.addField(DnComponents.RFC822NAME); already set
        profile.addField(DnComponents.RFC822NAME);
        profile.addField(DnComponents.RFC822NAME);
        profile.addField(DnComponents.RFC822NAME);
        //profile.setRequired(DnComponents.RFC822NAME,0,true); already set
        profile.setRequired(DnComponents.RFC822NAME,1,false);
        profile.setRequired(DnComponents.RFC822NAME,2,true);
        profile.setRequired(DnComponents.RFC822NAME,3,true);
        //profile.setUse(DnComponents.RFC822NAME, 0, true); already set
        profile.setUse(DnComponents.RFC822NAME, 1, false);
        profile.setUse(DnComponents.RFC822NAME, 2, false);
        profile.setUse(DnComponents.RFC822NAME, 3, false);
        //profile.setModifyable(DnComponents.RFC822NAME,0,false); already set
        profile.setModifyable(DnComponents.RFC822NAME,1,true);
        profile.setModifyable(DnComponents.RFC822NAME,2,false);
        profile.setModifyable(DnComponents.RFC822NAME,3,true);
        //profile.setValue(DnComponents.RFC822NAME,0,"test.com"); not used
        profile.setValue(DnComponents.RFC822NAME,1,"foobar.com");
        profile.setValue(DnComponents.RFC822NAME,2,"somefoo.com");
        profile.setValue(DnComponents.RFC822NAME,3,"somebar.com");
        // Make sure normal usage works
        try { 
            profile.doesUserFullfillEndEntityProfile("username","password",standardDN,
            		"rfc822name=test@test.com, rfc822name=test@anything.com, rfc822name=test@somefoo.com, "+
            		"dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",
            		SecConst.CERTPROFILE_FIXED_ENDUSER, false, false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0,
            		testca1, null);
            log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + "  = OK");
        } catch ( UserDoesntFullfillEndEntityProfile e ) {
        	assertTrue("Did not verify RFC822Name against email. "+e.getMessage() , false);        	
        }
        // Test missing required rfc822name field
        try { 
            profile.doesUserFullfillEndEntityProfile("username","password",standardDN,
            		"rfc822name=test@test.com, rfc822name=test@somefoo.com, "+
            		"dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",
            		SecConst.CERTPROFILE_FIXED_ENDUSER, false, false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0,
            		testca1, null);
        	assertTrue("Did not notice missing RFC822Name.", false);        	
        } catch ( UserDoesntFullfillEndEntityProfile e ) {
            log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + "  = OK (" + e.getMessage()+")");
        }
        // Try non-existing required "use end entity e-mail"
        try { 
            profile.doesUserFullfillEndEntityProfile("username","password",standardDN,
            		"rfc822name=test@nodomain.com, rfc822name=test@anything.com, rfc822name=test@somefoo.com, "+
            		"dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",
            		SecConst.CERTPROFILE_FIXED_ENDUSER, false, false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0,
            		testca1, null);
        	assertTrue("Did not check RFC822Name against e-mail field.", false);
        } catch ( UserDoesntFullfillEndEntityProfile e ) {
            log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + "  = OK (" + e.getMessage()+")");
        }
        // Try to ignore a required non-modifyable domain
        try { 
            profile.doesUserFullfillEndEntityProfile("username","password",standardDN,
            		"rfc822name=test@test.com, rfc822name=test@anything.com, rfc822name=test@somebar.com, "+
            		"dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",
            		SecConst.CERTPROFILE_FIXED_ENDUSER, false, false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0,
            		testca1, null);
        	assertTrue("Did not check RFC822Name against profile.", false);
        } catch ( UserDoesntFullfillEndEntityProfile e ) {
            log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + "  = OK (" + e.getMessage()+")");
        }
        // Use same as required non-mod field in non-req field
        try { 
            profile.doesUserFullfillEndEntityProfile("username","password",standardDN,
            		"rfc822name=test@test.com, rfc822name=test@anything.com, rfc822name=test@somefoo.com, rfc822name=test@somefoo.com, "+
            		"dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",
            		SecConst.CERTPROFILE_FIXED_ENDUSER, false, false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0,
            		testca1, null);
            log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + "  = OK");
        } catch ( UserDoesntFullfillEndEntityProfile e ) {
        	assertTrue("Did not check RFC822Name against profile." + e.getMessage(), false);
        }

        }{// New profile
        final EndEntityProfile profile = new EndEntityProfile();        
        
        
        // Set so CN=modifyable required, OU0={DEP1_1,DEP1_2} required, OU1={DEP2_1,DEP2_2} required, OU3=Optional, C=O{SE,DK} not required 
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.COUNTRY);
        
        profile.setRequired(DnComponents.ORGANIZATIONUNIT,0,false);
        profile.setRequired(DnComponents.ORGANIZATIONUNIT,1,true);
        profile.setRequired(DnComponents.ORGANIZATIONUNIT,2,false);
        profile.setRequired(DnComponents.ORGANIZATIONUNIT,3,true);
        profile.setRequired(DnComponents.ORGANIZATIONUNIT,4,false);
        
        profile.setModifyable(DnComponents.ORGANIZATIONUNIT,1,false);
        profile.setModifyable(DnComponents.ORGANIZATIONUNIT,3,false);
        profile.setModifyable(DnComponents.ORGANIZATIONUNIT,4,true);
        profile.setModifyable(DnComponents.COUNTRY,0,false);
        
        profile.setValue(DnComponents.ORGANIZATIONUNIT,1,"DEP1_1;DEP1_2");
        profile.setValue(DnComponents.ORGANIZATIONUNIT,3,"DEP2_1;DEP2_2");
        profile.setValue(DnComponents.ORGANIZATIONUNIT,4,"DEP3_1;DEP3_2");
        profile.setValue(DnComponents.COUNTRY,0,"SE;DK");
        
        profile.setValue(EndEntityProfile.AVAILCAS,0,""+testca1);
                
        // Test with two OU  (2 required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=,OU=DEP1_1,OU=,OU=DEP2_2,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Error Required OU fields wasn't checked propertly: " + e.getMessage(), false);
        	
        }     
        
        // Test with tree OU  (2 required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=,OU=DEP1_1,OU=,OU=DEP2_2,OU=DEP3_3,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Error Required OU fields wasn't checked propertly: " + e.getMessage(), false);        	
        } 
        
        profile.setModifyable(DnComponents.ORGANIZATIONUNIT,4,false);
        // Test with tree OU  (2 required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=,OU=DEP1_1,OU=,OU=DEP2_2,OU=DEP3_1,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Error Required OU fields wasn't checked propertly: " + e.getMessage(), false);        	
        }        
        
        // Test with tree OU  (2 required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=,OU=DEP1_1,OU=,OU=DEP2_2,OU=DEP3_3,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
            assertTrue("Error Required OU fields wasn't checked propertly " , false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }  
        }{
        // Test Reverse Checks
        // New profile
        final EndEntityProfile profile = new EndEntityProfile();
        profile.setReverseFieldChecks(true);
        
        // Set so CN=modifyable required, OU0=Modifyable not required, OU1=Modifyable not required, OU3=required {hard,soft}, C=O{SE,DK} not required 
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.COUNTRY);
        
        profile.setRequired(DnComponents.ORGANIZATIONUNIT,0,false);
        profile.setRequired(DnComponents.ORGANIZATIONUNIT,1,false);
        profile.setRequired(DnComponents.ORGANIZATIONUNIT,2,true);
        
        profile.setModifyable(DnComponents.ORGANIZATIONUNIT,0,true);
        profile.setModifyable(DnComponents.ORGANIZATIONUNIT,1,true);
        profile.setModifyable(DnComponents.ORGANIZATIONUNIT,2,false);
        profile.setModifyable(DnComponents.COUNTRY,0,false);
        
        profile.setValue(DnComponents.ORGANIZATIONUNIT,0,"");
        profile.setValue(DnComponents.ORGANIZATIONUNIT,1,"");
        profile.setValue(DnComponents.ORGANIZATIONUNIT,2,"HARD;SOFT");
        profile.setValue(DnComponents.COUNTRY,0,"SE;DK");
        
        profile.setValue(EndEntityProfile.AVAILCAS,0,""+testca1);
        
        // Test with one OU  (1 required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Error Reverse OU fields wasn't checked propertly: " + e.getMessage(), false);
        	
        }   
        
        // Test with two OU  (1 required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=DEP2_1,OU=HARD,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Error Reverse OU fields wasn't checked propertly: " + e.getMessage(), false);
        	
        }  
        
        // Test with three OU  (1 required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_1,OU=HARD,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Error Reverse OU fields wasn't checked propertly: " + e.getMessage(), false);
        	
        }  
        
        // Test with four OU  (3 allowed)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=DEP0_1,OU=DEP1_1,OU=DEP2_1,OU=HARD,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
            assertTrue("Error Reverse OU fields wasn't checked propertly" ,false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        } 
        
        // Test with wrong data in nonmodifiable field
 
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_1,OU=HARD2,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
            assertTrue("Error Reverse OU fields wasn't checked propertly", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        }   
        
        
        // Test that the right data is checked when a lesser number of field is used
        
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
           log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Error Reverse OU fields wasn't checked propertly: " + e.getMessage(), false);        	        	
        } 
        
        // Test with wrong data in nonmodifiable field when having only one ou
        
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=HARD2,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
            assertTrue("Error Reverse OU fields wasn't checked propertly", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        }  
        
        // Test with no ou
        
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,C=SE","null","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
            assertTrue("Error Reverse OU fields wasn't checked propertly", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        }  
        
        // Test Reverse checks of subject alt names

        
        // Set so CN=modifyable required, OU=Modifyable not required, OU1=Modifyable not required, OU3=required {hard,soft}, C=O{SE,DK} not required 
        profile.addField(DnComponents.IPADDRESS);
        profile.addField(DnComponents.IPADDRESS);
        profile.addField(DnComponents.IPADDRESS);
        profile.addField(DnComponents.DNSNAME);
        
        profile.setRequired(DnComponents.IPADDRESS,0,false);
        profile.setRequired(DnComponents.IPADDRESS,1,false);
        profile.setRequired(DnComponents.IPADDRESS,2,true);
        
        profile.setModifyable(DnComponents.IPADDRESS,0,true);
        profile.setModifyable(DnComponents.IPADDRESS,1,true);
        profile.setModifyable(DnComponents.IPADDRESS,2,false);
        profile.setModifyable(DnComponents.DNSNAME,0,false);
        
        profile.setValue(DnComponents.IPADDRESS,0,"");
        profile.setValue(DnComponents.IPADDRESS,1,"");
        profile.setValue(DnComponents.IPADDRESS,2,"10.1.1.1;10.2.2.2");
        profile.setValue(DnComponents.DNSNAME,0,"test1.se;test2.se");
        

        
        // Test with one IPAddress  (1 required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Error Reverse IPADDRESS fields wasn't checked propertly: " + e.getMessage(), false);
        	
        }        
        
        // Test with two IPAddress  (1 required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=DEP2_1,OU=HARD,C=SE","dnsname=test1.se,ipaddress=11.1.1.1,ipaddress=10.1.1.1","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Error Reverse IPADDRESS fields wasn't checked propertly: " + e.getMessage(), false);
        	
        }  
        
        // Test with three IPAddress  (1 required)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_1,OU=HARD,C=SE","dnsname=test1.se,ipaddress=12.1.1.1,ipaddress=11.1.1.1,ipaddress=10.1.1.1","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
          log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Error Reverse IPADDRESS fields wasn't checked propertly: " + e.getMessage(), false);
        	
        }  
        
        // Test with four IPAddress  (3 allowed)
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=DEP0_1,OU=DEP1_1,OU=DEP2_1,OU=HARD,C=SE","dnsname=test1.se,ipaddress=12.1.1.1,ipaddress=12.1.1.1,ipaddress=11.1.1.1,ipaddress=10.1.1.1","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
            assertTrue("Error Reverse IPADDRESS fields wasn't checked propertly" ,false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        } 
        
        // Test with wrong data in nonmodifiable field
 
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_1,OU=HARD2,C=SE","dnsname=test1.se,ipaddress=12.1.1.1,ipaddress=11.1.1.1,ipaddress=10.1.1.2","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
            assertTrue("Error Reverse IPADDRESS fields wasn't checked propertly", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        }   
        
        
        // Test that the right data is checked when a lesser number of field is used
        
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
           log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Error Reverse IPADDRESS fields wasn't checked propertly: " + e.getMessage(), false);        	        	
        } 
        
        // Test with wrong data in nonmodifiable field when having only one ou
        
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=HARD2,C=SE","dnsname=test1.se,ipaddress=11.1.1.1","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
            assertTrue("Error Reverse IPADDRESS fields wasn't checked propertly", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        }  
        
        // Test with no ou
        
        try{ 
          profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,C=SE","dnsname=test1.se","","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
            assertTrue("Error Reverse IPADDRESS fields wasn't checked propertly", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        }          


        // Test adding required fields for Subject Directory Attributes
        // Set so CN=modifyable required, OU=Modifyable not required, OU1=Modifyable not required, OU3=required {hard,soft}, C=O{SE,DK} not required 
        profile.addField(DnComponents.DATEOFBIRTH);
        profile.addField(DnComponents.PLACEOFBIRTH);
        profile.addField(DnComponents.GENDER);
        profile.addField(DnComponents.COUNTRYOFCITIZENSHIP);
        profile.addField(DnComponents.COUNTRYOFRESIDENCE);
        
        profile.setRequired(DnComponents.DATEOFBIRTH,0,false);
        profile.setRequired(DnComponents.PLACEOFBIRTH,0,false);
        profile.setRequired(DnComponents.GENDER,0,false);
        profile.setRequired(DnComponents.COUNTRYOFCITIZENSHIP,0,false);
        profile.setRequired(DnComponents.COUNTRYOFRESIDENCE,0,false);
        
        profile.setModifyable(DnComponents.DATEOFBIRTH,0,true);
        profile.setModifyable(DnComponents.PLACEOFBIRTH,0,true);
        profile.setModifyable(DnComponents.GENDER,0,true);
        profile.setModifyable(DnComponents.COUNTRYOFCITIZENSHIP,0,true);
        profile.setModifyable(DnComponents.COUNTRYOFRESIDENCE,0,false);
        
        profile.setValue(DnComponents.DATEOFBIRTH,0,"");
        profile.setValue(DnComponents.PLACEOFBIRTH,0,"");
        profile.setValue(DnComponents.GENDER,0,"");
        profile.setValue(DnComponents.COUNTRYOFCITIZENSHIP,0,"");
        profile.setValue(DnComponents.COUNTRYOFRESIDENCE,0,"SE");

        try{ 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","CountryOfCitizenship=FOO","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
        			false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
        	assertTrue("Error CountryOfCitizenship wasn't checked propertly", false);        	        	
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertEquals("Invalid COUNTRYOFCITIZENSHIP. Must be of length two.", e.getMessage());
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        try{ 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","CountryOfCitizenship=SE, CountryOfResidence=Foo","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
        			false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
        	assertTrue("Error CountryOfCitizenship wasn't checked propertly", false);        	        	
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertEquals("Invalid COUNTRYOFRESIDENCE. Must be of length two.", e.getMessage());
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        try{ 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","CountryOfCitizenship=SE, CountryOfResidence=TR","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
        			false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
        	assertTrue("Error CountryOfCitizenship wasn't checked propertly", false);        	        	
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertEquals("Field COUNTRYOFRESIDENCE data didn't match requirement of end entity profile.", e.getMessage());
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        try{ 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","CountryOfCitizenship=SE, CountryOfResidence=SE, Gender=M, PlaceOfBirth=Stockholm","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
        			false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Error Subject Dir Attributes wasn't checked propertly", false);        	        	
        } 
        try{ 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","DateOfBirth=189901, CountryOfCitizenship=SE, CountryOfResidence=SE","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
        			false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
        	assertTrue("Error DateOfBirth wasn't checked propertly", false);        	        	
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertEquals("Invalid DATEOFBIRTH. Must be of length eight.", e.getMessage());
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        try{ 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","DateOfBirth=189901AA, CountryOfCitizenship=SE, CountryOfResidence=SE","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
        			false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
        	assertTrue("Error DateOfBirth wasn't checked propertly", false);        	        	
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertEquals("Invalid DATEOFBIRTH. Must be only numbers.", e.getMessage());
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        try{ 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","DateOfBirth=18990101, CountryOfCitizenship=SE, CountryOfResidence=SE","",SecConst.CERTPROFILE_FIXED_ENDUSER, false,
        			false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue("Error DateOfBirth wasn't checked propertly", false);        	        	
        } 
        }{
        // Test time constraints
        final EndEntityProfile profile = new EndEntityProfile();
        Date now = new Date();
        Date endOfTime = new Date(Long.MAX_VALUE);
        FastDateFormat sm = FastDateFormat.getInstance("yyyy-MM-dd HH:mm");
        String staticNow = sm.format(now);
        String relativeNow = "0:00:00";
        String staticEndOfTime = sm.format(endOfTime);
        String relativeEndOfTime = "33000:00:00"; // ~100 years
        String staticInvalid = "XXXX-XX-XX XX:XX PM";
        String relativeInvalid = "XXXXX:XXX:XXX";
        String relativeNegative = "-10:00:00";
        ExtendedInformation ei = new ExtendedInformation();
        // Use empty, should fail
        profile.setValue(EndEntityProfile.AVAILCAS,0,""+testca1);
        profile.setUse(EndEntityProfile.STARTTIME, 0, true);
        profile.setUse(EndEntityProfile.ENDTIME, 0, false);
        profile.setValue(EndEntityProfile.STARTTIME, 0, "");
        profile.setValue(EndEntityProfile.ENDTIME, 0, "");
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, "");
        try { 
        	// Custom starttime can be empty or null
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	assertTrue("Error: Empty start time was not checked correctly.", false);
        } 
        profile.setUse(EndEntityProfile.STARTTIME, 0, false);
        profile.setUse(EndEntityProfile.ENDTIME, 0, true);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, "");
        try { 
        	// Custom endtime can be empty or null
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	assertTrue("Error: Empty end time was not checked correctly.", false);
        } 
        // Static times work?
        profile.setUse(EndEntityProfile.STARTTIME, 0, true);
        profile.setUse(EndEntityProfile.ENDTIME, 0, true);
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, staticNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticEndOfTime);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	assertTrue("Error: Static times does not work. ("+e.getMessage()+")", false);
        } 
        // Relative times work?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, relativeNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, relativeEndOfTime);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	assertTrue("Error: Relative times does not work.", false);
        } 
        // Static start, rel end work?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, staticNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, relativeEndOfTime);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	assertTrue("Error: Static start time w relative end time does not work.", false);
        } 
        // Rel start, static end work?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, relativeNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticEndOfTime);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	assertTrue("Error: Relative start time w static end time does not work.", false);
        } 
        // Negative relative start times work?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, relativeNegative);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticEndOfTime);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	assertTrue("Error: Possible to use negative start time.", false);
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Negative relative end times work?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, staticNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, relativeNegative);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	assertTrue("Error: Possible to use negative end time.", false);
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Static end before start ok?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, staticEndOfTime);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticNow);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	assertTrue("Error: Static end time before static start time allowed.", false);
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Relative end before start ok?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, relativeEndOfTime);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, relativeNow);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	assertTrue("Error: Relative end time before relative start time allowed.", false);
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Invalid static start ok?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, staticInvalid);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticEndOfTime);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	assertTrue("Error: Invalid static start time allowed.", false);
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Invalid static end ok?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, staticNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticInvalid);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	assertTrue("Error: Invalid static start time allowed.", false);
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Invalid relative start ok?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, relativeInvalid);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticEndOfTime);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	assertTrue("Error: Invalid relative start time allowed.", false);
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Invalid relative end ok?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, relativeNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticInvalid);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	assertTrue("Error: Invalid relative start time allowed.", false);
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }
        // Is this Java-version parsing dates correctly?
        long magicDateTime = 1181040300000L;	// "12:45 PM" in US Locale
		String value1 = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.US).format(new Date(magicDateTime));
		String value2 = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US).format(
				DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.US).parse(value1));
		long magicDateTime2 = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US).parse(value2).getTime();
		if ( magicDateTime != magicDateTime2 ) {
	        assertTrue("Error: Java does not parse dates correctly. "+magicDateTime+" "+magicDateTime2+" "+value1+" "+value2, false);
		}
        }{
        // Test allow multiple requests
        final EndEntityProfile profile = new EndEntityProfile();
        final ExtendedInformation ei = new ExtendedInformation();
        // Use empty, should fail
        profile.setValue(EndEntityProfile.AVAILCAS,0,""+testca1);
        profile.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, false);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	assertTrue("Error: Allowedrequests not checked correctly, should be allowed.", false);
        } 
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, "2");
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	assertTrue("Error: Allowed requests was not checked correctly, should not be allowed.", false);
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        profile.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        try { 
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith", "","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	assertTrue("Error: Allowedrequests not checked correctly, should be allowed.", false);
        } 
        }{
        // New profile
        final EndEntityProfile profile = new EndEntityProfile();
        
        
        // Set so maxFailedLogins=non-modifyable required 
        profile.addField(EndEntityProfile.MAXFAILEDLOGINS);
        profile.setUse(EndEntityProfile.MAXFAILEDLOGINS,0,true);
        profile.setRequired(EndEntityProfile.MAXFAILEDLOGINS,0,true);
        profile.setModifyable(EndEntityProfile.MAXFAILEDLOGINS,0,false);
        profile.setValue(EndEntityProfile.MAXFAILEDLOGINS,0,"7");

        profile.setValue(EndEntityProfile.AVAILCAS,0,""+testca1);
        
        try {
        	final ExtendedInformation ei = new ExtendedInformation();
        	ei.setMaxLoginAttempts(1234);
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith","","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false,false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        	fail("Error: maxFailedLogins was not checked correctly, should not be allowed.");
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	// OK
        }
        
        try {
        	final ExtendedInformation ei = new ExtendedInformation();
        	ei.setMaxLoginAttempts(7);
        	profile.doesUserFullfillEndEntityProfile("username","password","CN=John Smith","","","",SecConst.CERTPROFILE_FIXED_ENDUSER,
        			false,false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, ei);
        } catch (UserDoesntFullfillEndEntityProfile e) {
        	log.error(e.getMessage(), e);
        	fail("Error: maxFailedLogins was not checked correctly, should be allowed.");
        }

        log.trace("<test01fulfillEndEntityProfiles()");
        }
    } // test01fulfillEndEntityProfiles
    
    public void test02fulfillEndEntityProfilesAvailableCAs() throws Exception {
        EndEntityProfile profile = new EndEntityProfile();
        
        // Dummy caids
        int testca1 = 2;
        int testca2 = 3;
        
        // Set so CN=modifyable required, OU0={DEP1_1,DEP1_2} required, OU1={DEP2_1,DEP2_2} required, C=OU1={SE,DK} not required 
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.addField(DnComponents.COUNTRY);
        
        profile.setRequired(DnComponents.ORGANIZATIONUNIT,0,true);
        profile.setRequired(DnComponents.ORGANIZATIONUNIT,1,true);
        
        profile.setModifyable(DnComponents.ORGANIZATIONUNIT,0,false);
        profile.setModifyable(DnComponents.ORGANIZATIONUNIT,1,false);
        profile.setModifyable(DnComponents.COUNTRY,0,false);
        
        profile.setValue(DnComponents.ORGANIZATIONUNIT,0,"DEP1_1;DEP1_2");
        profile.setValue(DnComponents.ORGANIZATIONUNIT,1,"DEP2_1;DEP2_2");
        profile.setValue(DnComponents.COUNTRY,0,"SE;DK");
        
        profile.setValue(EndEntityProfile.AVAILCAS,0,""+testca1);

        // Test right CA
        try{ 
        	profile.doesUserFullfillEndEntityProfile("username","password",standardDN,null,"","test11@test.com",SecConst.CERTPROFILE_FIXED_SUBCA, false,
        			false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
        }catch(UserDoesntFullfillEndEntityProfile e){        	        	
        	assertTrue(e.getMessage(), false);
        }
        
        // Test Wrong CA
        try{ 
        	profile.doesUserFullfillEndEntityProfile("username","password",standardDN,null,"","test11@test.com",SecConst.CERTPROFILE_FIXED_SUBCA, false,
        			false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca2, null);
        	assertTrue("Improper check of available ca's.", false);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	//log.debug(e.getMessage());
        	assertEquals("Couldn't find CA (3) among End Entity Profiles Available CAs.", e.getMessage());
        }

        // Set Any CA available
        profile.setValue(EndEntityProfile.AVAILCAS,0,""+SecConst.ALLCAS);

        // Test right CA
        try{ 
        	profile.doesUserFullfillEndEntityProfile("username","password",standardDN,null,"","test11@test.com",SecConst.CERTPROFILE_FIXED_SUBCA, false,
        			false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca1, null);
        }catch(UserDoesntFullfillEndEntityProfile e){        	        	
        	assertTrue(e.getMessage(), false);
        }
        
        // Test Wrong CA
        try{ 
        	profile.doesUserFullfillEndEntityProfile("username","password",standardDN,null,"","test11@test.com",SecConst.CERTPROFILE_FIXED_SUBCA, false,
        			false,false,SecConst.TOKEN_SOFT_BROWSERGEN, 0, testca2, null);
        }catch(UserDoesntFullfillEndEntityProfile e){
        	assertTrue(e.getMessage(), false);
        }

    }
} // TestUserFullfillEndEntityProfile
