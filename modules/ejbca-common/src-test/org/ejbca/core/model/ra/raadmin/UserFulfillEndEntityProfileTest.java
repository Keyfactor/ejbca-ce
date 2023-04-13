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

package org.ejbca.core.model.ra.raadmin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.text.DateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.config.EABConfiguration;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.ExtendedInformationFields;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.keyfactor.util.certificate.DnComponents;

/**
 * Tests the end entity profile entity bean profile checks only
 *
 */
public class UserFulfillEndEntityProfileTest {
    private static final Logger log = Logger.getLogger(UserFulfillEndEntityProfileTest.class);

    private static final String STANDARD_DN = "CN=John Smith,OU=DEP1_1,OU=DEP2_1,C=SE";
    private static final int TEST_CA_1 = 2;
    private static final int TEST_CA_2 = 3;
    
    private static final String SAMPLECABFORGANICATIONID = "VATSE-123456789"; 
    
    private static final CertificateProfile certProfileEndUser = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    private static final CertificateProfile certProfileRootCa = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
    private static final CertificateProfile certProfileSubCa = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
    
    private EndEntityProfile createBasicProfile() {
        final EndEntityProfile profile = new EndEntityProfile();

        // Set so CN=modifyable required, OU0={DEP1_1,DEP1_2} required, OU1={DEP2_1,DEP2_2} required, C=OU1={SE,DK} not required 
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.COUNTRY);
        
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,0,true);
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,1,true);
        profile.setModifyable(DnComponents.ORGANIZATIONALUNIT,0,false);
        profile.setModifyable(DnComponents.ORGANIZATIONALUNIT,1,false);
        profile.setModifyable(DnComponents.COUNTRY,0,false);
        
        profile.setValue(DnComponents.ORGANIZATIONALUNIT,0,"DEP1_1;DEP1_2");
        profile.setValue(DnComponents.ORGANIZATIONALUNIT,1,"DEP2_1;DEP2_2");
        profile.setValue(DnComponents.COUNTRY,0,"SE;DK");
        
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));
        return profile;
    }
    
    private EndEntityProfile createProfileWithReversedChecks() {
        final EndEntityProfile profile = new EndEntityProfile();
        profile.setReverseFieldChecks(true);
        
        // Set so CN=modifyable required, OU0=Modifyable not required, OU1=Modifyable not required, OU3=required {hard,soft}, C=O{SE,DK} not required 
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.COUNTRY);
        
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,0,false);
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,1,false);
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,2,true);
        
        profile.setModifyable(DnComponents.ORGANIZATIONALUNIT,0,true);
        profile.setModifyable(DnComponents.ORGANIZATIONALUNIT,1,true);
        profile.setModifyable(DnComponents.ORGANIZATIONALUNIT,2,false);
        profile.setModifyable(DnComponents.COUNTRY,0,false);
        
        profile.setValue(DnComponents.ORGANIZATIONALUNIT,0,"");
        profile.setValue(DnComponents.ORGANIZATIONALUNIT,1,"");
        profile.setValue(DnComponents.ORGANIZATIONALUNIT,2,"HARD;SOFT");
        profile.setValue(DnComponents.COUNTRY,0,"SE;DK");
        
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));
        return profile;
    }

    /**
     * Test the profile fulfilling checks for Subject DN.
     */
    @Test
    public void fulfillSubjectDn() throws Exception {
        log.trace(">fulfillSubjectDn");
        int currentSubTest = 1;
        final EndEntityProfile profile = createBasicProfile();
        
        // Test completely errornous DN
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password","blabla","","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Profile does not check DN at all.");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + " = OK");
        }

        // Test correct DN
        profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,"null","","",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser,null);
        log.debug("End Entity Profile Fulfill Test " + (currentSubTest++) + " " + " = OK");
        
        // Test no username even though is required
        try{ 
          profile.doesUserFulfillEndEntityProfile("","password",STANDARD_DN,"null","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("UserName is not checked even though it's required");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Profile Fulfill Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");	
        }
        
        // Test no password even though is required
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","",STANDARD_DN,"null","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Password is not checked even though it's required");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Profile Test Fulfill " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test with no CN (required)
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password","OU=DEP1_1,OU=DEP2_1,C=SE","null","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Error Required CN field wasn't checked");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test with only one OU  (2 required)
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=DEP2_1,C=SE","null","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Error Required OU field wasn't checked");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test were second OU have the wrong value (Dep2_1 or Dep2_2)
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_3,C=SE","null","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Error value of second OU field wasn't checked");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage()+ " = OK");
        }
        
        // Test without C (not required)
        profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_2","null","","",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + " = OK");
        
        // Test illegal value of  C (SE or DK)
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_2, C=NO","null","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Inproper check of C value.");
        }catch(EndEntityProfileValidationException e){        	        	
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest) + " " + e.getMessage() + " = OK");
        }
        
        // Test Matter IoT VID and PID
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password","CN=Matter DAC,VID=FFF1,PID=8000","null","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Inproper check of VID and PID value.");
        }catch(EndEntityProfileValidationException e){                      
            log.debug("End Entity Fulfill Profile Test " + (currentSubTest) + " " + e.getMessage() + " = OK");
        }
        
        profile.addField(DnComponents.VID);
        profile.addField(DnComponents.PID);
        // Should pass now
        profile.doesUserFulfillEndEntityProfile("username","password","OU=DEP1_1,OU=DEP2_2,CN=Matter DAC,VID=FFF1,PID=8000","null","","",
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        
        log.trace("<fulfillSubjectDn");
    }

    /**
     * Test the profile fulfilling checks for Subject Alternative Names
     */
    @Test
    public void fulfillAltNames() throws Exception {
        log.trace(">fulfillAltNames");
        
        int currentSubTest = 1;
        final EndEntityProfile profile = createBasicProfile();

        // Add some subject altname fields
        profile.addField(DnComponents.RFC822NAME);
        profile.addField(DnComponents.DNSNAME);
        profile.addField(DnComponents.UPN);
        profile.addField(DnComponents.IPADDRESS);
        
        profile.setUse(DnComponents.RFC822NAME,0,true);
        
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

        profile.setEmailRequired(true);
        profile.setEmailModifiable(false);
        profile.setEmailDomain("test.com;primekey.se");
        
        // Test completely errornous Alt Name
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,"blabla","","test@test.com",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Profile does not check altname at all.");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + " = OK");
        }

        // Test correct Alt Name
        profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,"RFC822NAME=test@test.com, dnsname=test.primekey.se, Upn=test@primekey.se, ipaddress=11.11.1.2","","test@test.com",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Profile Fulfill Test " + (currentSubTest++) + " " + " = OK");
        
        // Test with no RFC822NAME (required)
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,"dnsname=test.primekey.se, Upn=test@primekey.se, ipaddress=11.11.1.2","","test@test.com",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Error Required RFC822NAME field wasn't checked");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test with one RFC822NAME to many
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN, "rfc822name=test@test.com, rfc822name=test@primekey.se, dnsname=test.primekey.se, Upn=test@primekey.se, ipaddress=11.11.1.2","","test@test.com",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("To many RFC822 names fields wasn't checked");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test that only domain is checked for RFC822name and UPN
        profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN, "rfc822name=test@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + "  = OK");
        
        // Test were DNS have illegal value
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,"rfc822name=test@test.com, dnsname=test2.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Error value of DNS not checked.");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage()+ " = OK");
        }
        
        // Test without IPADDRESS (required)
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,"rfc822name=test@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Error not checking number of IPADDRESS properly.");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + " = OK");
        	
        }
        
        
        // Test without email field (required) 1
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,"rfc822name=test@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.1","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Inproper check of email field.");
        }catch(EndEntityProfileValidationException e){        	        	
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test without email field (required) 2
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,"rfc822name=test@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.1","","null",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Inproper check of email field.");
        }catch(EndEntityProfileValidationException e){        	        	
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test without email field (required) 3
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,"rfc822name=test@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se,ipaddress=11.11.1.1","",null,
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Inproper check of email field.");
        }catch(EndEntityProfileValidationException e){        	        	
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test illegal value of  email field (test.com or primekey.se) 1
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,"rfc822name=test11@test1.com, dnsname=test.primekey.se, Upn=test12@primekey.se,ipaddress=11.11.1.1","","test11@test1.com",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Inproper check of email field values.");
        }catch(EndEntityProfileValidationException e){        	        	
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        profile.setAvailableCertificateProfileIds(Arrays.asList(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA));
        
        // Test illegal value of  Certificate Profile
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,"rfc822name=test11@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se,ipaddress=11.11.1.1","","test11@test.com",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileRootCa, null);
          fail("Inproper check of certificate profile values.");
        }catch(EndEntityProfileValidationException e){        	        	
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " " + e.getMessage() + " = OK");
        }
        
        // Test Wrong CA
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,"rfc822name=test11@test.com, dnsname=test.primekey.se, Upn=test12@primekey.se,ipaddress=11.11.1.1","","test11@test.com",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_2, null, certProfileSubCa, null);
          fail("Inproper check of available ca's.");
        }catch(EndEntityProfileValidationException e){        	        	
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
        profile.setValue(DnComponents.RFC822NAME,2,"test@somefoo.com");
        profile.setValue(DnComponents.RFC822NAME,3,"somebar.com");
        // Make sure normal usage works
        /*
         * Normal usage test moved down to testProfileWithRfc822Name()
         */
        // Test missing required rfc822name field
        try { 
            profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,
            		"rfc822name=test@test.com, rfc822name=test@somefoo.com, "+
            		"dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",
            		CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false,false,SecConst.TOKEN_SOFT_BROWSERGEN,
            		TEST_CA_1, null, certProfileEndUser, null);
            fail("Did not notice missing RFC822Name.");        	
        } catch ( EndEntityProfileValidationException e ) {
            log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + "  = OK (" + e.getMessage()+")");
        }
        // Try non-existing required "use end entity e-mail"
        try { 
            profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,
            		"rfc822name=test@nodomain.com, rfc822name=test@anything.com, rfc822name=test@somefoo.com, "+
            		"dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",
            		CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false,false,SecConst.TOKEN_SOFT_BROWSERGEN,
            		TEST_CA_1, null, certProfileEndUser, null);
            fail("Did not check RFC822Name against e-mail field.");
        } catch ( EndEntityProfileValidationException e ) {
            log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + "  = OK (" + e.getMessage()+")");
        }
        // Try to ignore a required non-modifyable domain
        try { 
            profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,
            		"rfc822name=test@test.com, rfc822name=test@anything.com, rfc822name=test@somebar.com, "+
            		"dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",
            		CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false,false,SecConst.TOKEN_SOFT_BROWSERGEN,
            		TEST_CA_1, null, certProfileEndUser, null);
            fail("Did not check RFC822Name against profile.");
        } catch ( EndEntityProfileValidationException e ) {
            log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + "  = OK (" + e.getMessage()+")");
        }
        // Use same as required non-mod field in non-req field
        profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,
        		"rfc822name=test@test.com, rfc822name=test@anything.com, rfc822name=test@somefoo.com, rfc822name=test@somefoo.com, "+
        		"dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",
        		CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false,false,SecConst.TOKEN_SOFT_BROWSERGEN,
        		TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest) + "  = OK");
        log.trace("<fulfillAltNames");
    }

    /**
     * Tests profile fulfilling checks with multiple identical fields
     */
    @Test
    public void fulfillWithMultiple() throws Exception {
        log.trace(">fulfillWithMultiple");
        int currentSubTest = 1;
        final EndEntityProfile profile = new EndEntityProfile();        
        
        // Set so CN=modifyable required, OU0={DEP1_1,DEP1_2} required, OU1={DEP2_1,DEP2_2} required, OU3=Optional, C=O{SE,DK} not required 
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.COUNTRY);
        
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,0,false);
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,1,true);
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,2,false);
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,3,true);
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,4,false);
        
        profile.setModifyable(DnComponents.ORGANIZATIONALUNIT,1,false);
        profile.setModifyable(DnComponents.ORGANIZATIONALUNIT,3,false);
        profile.setModifyable(DnComponents.ORGANIZATIONALUNIT,4,true);
        profile.setModifyable(DnComponents.COUNTRY,0,false);
        
        profile.setValue(DnComponents.ORGANIZATIONALUNIT,1,"DEP1_1;DEP1_2");
        profile.setValue(DnComponents.ORGANIZATIONALUNIT,3,"DEP2_1;DEP2_2");
        profile.setValue(DnComponents.ORGANIZATIONALUNIT,4,"DEP3_1;DEP3_2");
        profile.setValue(DnComponents.COUNTRY,0,"SE;DK");
        
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));
                
        // Test with two OU  (2 required)
        profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=,OU=DEP1_1,OU=,OU=DEP2_2,C=SE","null","","",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");

        // Test with tree OU  (2 required)
        profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=,OU=DEP1_1,OU=,OU=DEP2_2,OU=DEP3_3,C=SE","null","","",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        
        profile.setModifyable(DnComponents.ORGANIZATIONALUNIT,4,false);

        // Test with tree OU  (2 required)
        profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=,OU=DEP1_1,OU=,OU=DEP2_2,OU=DEP3_1,C=SE","null","","",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        
        // Test with tree OU  (2 required)
        try { 
          profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=,OU=DEP1_1,OU=,OU=DEP2_2,OU=DEP3_3,C=SE","null","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Error Required OU fields wasn't checked propertly");
        } catch (EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest) + " = OK");
        }
        log.trace("<fulfillWithMultiple");
    }
    
    /**
     * Tests Subject DN fulfilling checks with "reverse field checks" enabled.
     */
    @Test
    public void fulfillSubjectDnReversedChecks() throws Exception {
        log.trace(">fulfillSubjectDnReversedChecks");
        int currentSubTest = 1;
        // Test Reverse Checks
        final EndEntityProfile profile = createProfileWithReversedChecks();
        
        // Test with one OU  (1 required)
        profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","null","","",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");

        // Test with two OU  (1 required)
        profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=DEP2_1,OU=HARD,C=SE","null","","",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");

        // Test with three OU  (1 required)
        profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_1,OU=HARD,C=SE","null","","",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        
        // Test with four OU  (3 allowed)
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=DEP0_1,OU=DEP1_1,OU=DEP2_1,OU=HARD,C=SE","null","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Error Reverse OU fields wasn't checked propertly");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        } 
        
        // Test with wrong data in nonmodifiable field
 
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_1,OU=HARD2,C=SE","null","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
          fail("Error Reverse OU fields wasn't checked propertly");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        }   
        
        
        // Test that the right data is checked when a lesser number of field is used
        profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","null","","",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");

        // Test with wrong data in nonmodifiable field when having only one ou
        
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=HARD2,C=SE","null","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
            fail("Error Reverse OU fields wasn't checked propertly");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        }  
        
        // Test with no ou
        
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","passworCerd","CN=John Smith,C=SE","null","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
            fail("Error Reverse OU fields wasn't checked propertly");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }
        log.trace("<fulfillSubjectDnReversedChecks");
    }

    /**
     * Tests Subject DN fulfilling checks with "reverse field checks" enabled.
     */
    @Test
    public void fulfillSanReversedChecks() throws Exception {
        log.trace(">fulfillSanReversedChecks");
        int currentSubTest = 1;
        // Test Reverse Checks
        final EndEntityProfile profile = createProfileWithReversedChecks();
        
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
        profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","","",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        
        // Test with two IPAddress  (1 required)
        profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=DEP2_1,OU=HARD,C=SE","dnsname=test1.se,ipaddress=11.1.1.1,ipaddress=10.1.1.1","","",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");

        // Test with three IPAddress  (1 required)
        profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_1,OU=HARD,C=SE","dnsname=test1.se,ipaddress=12.1.1.1,ipaddress=11.1.1.1,ipaddress=10.1.1.1","","",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        
        // Test with four IPAddress  (3 allowed)
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=DEP0_1,OU=DEP1_1,OU=DEP2_1,OU=HARD,C=SE","dnsname=test1.se,ipaddress=12.1.1.1,ipaddress=12.1.1.1,ipaddress=11.1.1.1,ipaddress=10.1.1.1","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
            fail("Error Reverse IPADDRESS fields wasn't checked propertly");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        } 
        
        // Test with wrong data in nonmodifiable field
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=DEP1_1,OU=DEP2_1,OU=HARD2,C=SE","dnsname=test1.se,ipaddress=12.1.1.1,ipaddress=11.1.1.1,ipaddress=10.1.1.2","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
            fail("Error Reverse IPADDRESS fields wasn't checked propertly");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        }   
        
        // Test that the right data is checked when a lesser number of field is used
        profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","","",
                                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
                                                false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");

        // Test with wrong data in nonmodifiable field when having only one ou
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=HARD2,C=SE","dnsname=test1.se,ipaddress=11.1.1.1","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
            fail("Error Reverse IPADDRESS fields wasn't checked propertly");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        }  
        
        // Test with no OU
        try{ 
          profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,C=SE","dnsname=test1.se","","",
                                                   CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
          		                                   false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
            fail("Error Reverse IPADDRESS fields wasn't checked propertly");
        }catch(EndEntityProfileValidationException e){
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        	
        }
        log.trace("<fulfillSanReversedChecks");
    }

    /**
     * Tests Subject Alternative Name fulfilling checks with "reverse field checks" enabled.
     */
    @Test
    public void fulfillSubjectDirAttributesReversedChecks() throws Exception {
        log.trace(">fulfillSubjectDirAttributesReversedChecks");
        int currentSubTest = 1;
        final EndEntityProfile profile = createProfileWithReversedChecks();
        profile.addField(DnComponents.IPADDRESS);
        profile.addField(DnComponents.DNSNAME);
        
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
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","CountryOfCitizenship=FOO","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
        	                                         false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        	fail("Error CountryOfCitizenship wasn't checked propertly");        	        	
        }catch(EndEntityProfileValidationException e){
        	assertEquals("Invalid COUNTRYOFCITIZENSHIP. Must be of length two.", e.getMessage());
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        try{ 
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","CountryOfCitizenship=SE, CountryOfResidence=Foo","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
        	                                         false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        	fail("Error CountryOfCitizenship wasn't checked propertly");        	        	
        }catch(EndEntityProfileValidationException e){
        	assertEquals("Invalid COUNTRYOFRESIDENCE. Must be of length two.", e.getMessage());
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        try{ 
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","CountryOfCitizenship=SE, CountryOfResidence=TR","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
        	                                         false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        	fail("Error CountryOfCitizenship wasn't checked propertly");        	        	
        }catch(EndEntityProfileValidationException e){
        	assertEquals("Field COUNTRYOFRESIDENCE data didn't match requirement of end entity profile.", e.getMessage());
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
    	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","CountryOfCitizenship=SE, CountryOfResidence=SE, Gender=M, PlaceOfBirth=Stockholm","",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
    	                                         false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
    	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        try{ 
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","DateOfBirth=189901, CountryOfCitizenship=SE, CountryOfResidence=SE","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
        	                                         false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        	fail("Error DateOfBirth wasn't checked propertly");        	        	
        }catch(EndEntityProfileValidationException e){
        	assertEquals("Invalid DATEOFBIRTH. Must be of length eight.", e.getMessage());
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        try{ 
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","DateOfBirth=189901AA, CountryOfCitizenship=SE, CountryOfResidence=SE","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
        			false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
        	fail("Error DateOfBirth wasn't checked propertly");        	        	
        }catch(EndEntityProfileValidationException e){
        	assertEquals("Invalid DATEOFBIRTH. Must be only numbers.", e.getMessage());
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }
    	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith,OU=HARD,C=SE","dnsname=test1.se,ipaddress=10.1.1.1","DateOfBirth=18990101, CountryOfCitizenship=SE, CountryOfResidence=SE","",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false,
    	                                         false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileEndUser, null);
    	log.debug("End Entity Fulfill Profile Test " + (currentSubTest) + " = OK");
    	log.trace("<fulfillSubjectDirAttributesReversedChecks");
    }

    /**
     * Tests validity start time / end time fulfilling checks
     */
    @Test
    public void testfulfillEndEntityProfilesTimeConstraints() throws Exception {
        log.trace(">testfulfillEndEntityProfilesTimeConstraints");
        int currentSubTest = 1;
        // Test time constraints
        final EndEntityProfile profile = new EndEntityProfile();
        Date now = new Date();
        FastDateFormat sm = FastDateFormat.getInstance("yyyy-MM-dd HH:mm");
        String staticNow = sm.format(now);
        String relativeNow = "0:00:00";
        String staticEndOfTime = "9999-12-31 23:59"; // unlimited end date according to RFC5280 section 4.1.2.5
        String relativeEndOfTime = "3300:00:00"; // ~100 years
        String staticInvalid = "XXXX-XX-XX XX:XX PM";
        String relativeInvalid = "XXXXX:XXX:XXX";
        String relativeNegative = "-10:00:00";
        ExtendedInformation ei = new ExtendedInformation();
        // Use empty, should fail
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));
        profile.setValidityStartTimeUsed(true);
        profile.setValidityEndTimeUsed(false);
        profile.setValidityStartTime("");
        profile.setValidityEndTime("");
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, "");
    	// Custom starttime can be empty or null
    	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
    	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
    	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        profile.setValidityStartTimeUsed(false);
        profile.setValidityEndTimeUsed(true);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, "");
    	// Custom endtime can be empty or null
    	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
    	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
    	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        // Static times work?
        profile.setValidityStartTimeUsed(true);
        profile.setValidityEndTimeUsed(true);
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, staticNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticEndOfTime);
    	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
    	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
    	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        // Relative times work?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, relativeNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, relativeEndOfTime);
    	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
    	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
    	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        // Static start, rel end work?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, staticNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, relativeEndOfTime);
    	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
    	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
    	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        // Rel start, static end work?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, relativeNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticEndOfTime);
    	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
    	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
    	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        // Negative relative start times work?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, relativeNegative);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticEndOfTime);
        try { 
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
        	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
        	fail("Error: Possible to use negative start time.");
        } catch (EndEntityProfileValidationException e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Negative relative end times work?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, staticNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, relativeNegative);
        try { 
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
        	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
        	fail("Error: Possible to use negative end time.");
        } catch (EndEntityProfileValidationException e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Static end before start ok?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, staticEndOfTime);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticNow);
        try { 
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
        	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
        	fail("Error: Static end time before static start time allowed.");
        } catch (EndEntityProfileValidationException e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Relative end before start ok?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, relativeEndOfTime);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, relativeNow);
        try { 
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
        	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
        	fail("Error: Relative end time before relative start time allowed.");
        } catch (EndEntityProfileValidationException e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Invalid static start ok?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, staticInvalid);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticEndOfTime);
        try { 
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
        	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
        	fail("Error: Invalid static start time allowed.");
        } catch (EndEntityProfileValidationException e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Invalid static end ok?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, staticNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticInvalid);
        try { 
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
        	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
        	fail("Error: Invalid static start time allowed.");
        } catch (EndEntityProfileValidationException e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Invalid relative start ok?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, relativeInvalid);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticEndOfTime);
        try { 
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
        	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
        	fail("Error: Invalid relative start time allowed.");
        } catch (EndEntityProfileValidationException e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        } 
        // Invalid relative end ok?
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, relativeNow);
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, staticInvalid);
        try { 
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
        	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
        	fail("Error: Invalid relative start time allowed.");
        } catch (EndEntityProfileValidationException e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest) + " = OK");
        }
        // Is this Java-version parsing dates correctly?
        long magicDateTime = 1181040300000L;	// "12:45 PM" in US Locale
		String value1 = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.US).format(new Date(magicDateTime));
		String value2 = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US).format(
				DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.US).parse(value1));
		long magicDateTime2 = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US).parse(value2).getTime();
		if ( magicDateTime != magicDateTime2 ) {
	        fail("Error: Java does not parse dates correctly. "+magicDateTime+" "+magicDateTime2+" "+value1+" "+value2);
		}
		log.trace("<testfulfillEndEntityProfilesTimeConstraints");
    }

    /**
     * Tests disallowing/allowing multiple requests.
     */
    @Test
    public void allowMultipleRequests() throws Exception {
        log.trace(">allowMultipleRequests");
        int currentSubTest = 1;
        // Test allow multiple requests
        final EndEntityProfile profile = new EndEntityProfile();
        final ExtendedInformation ei = new ExtendedInformation();
        // Use empty, should fail
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));
        profile.setAllowedRequestsUsed(false);
    	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
    			false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
    	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, "2");
        try { 
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
        	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
        	fail("Error: Allowed requests was not checked correctly, should not be allowed.");
        } catch (EndEntityProfileValidationException e) {
        	log.debug("End Entity Fulfill Profile Test " + (currentSubTest++) + " = OK");
        }
        profile.setAllowedRequestsUsed(true);
    	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith", "","","",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
    	                                         false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
    	log.debug("End Entity Fulfill Profile Test " + (currentSubTest) + " = OK");
    	log.trace("<allowMultipleRequests");
    }

    /**
     * Tests restricted number of login attempts.
     */
    @Test
    public void maxFailedLogins() throws Exception {
        log.trace(">maxFailedLogins");
        final EndEntityProfile profile = new EndEntityProfile();
        
        // Set so maxFailedLogins=non-modifyable required 
        profile.setMaxFailedLoginsUsed(true);
        profile.setMaxFailedLoginsModifiable(false);
        profile.setMaxFailedLogins(7);
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));
        
        try {
        	final ExtendedInformation ei = new ExtendedInformation();
        	ei.setMaxLoginAttempts(1234);
        	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith","","","",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
        	                                         false,false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);
        	fail("Error: maxFailedLogins was not checked correctly, should not be allowed.");
        } catch (EndEntityProfileValidationException e) {
        	// OK
        }
        
    	final ExtendedInformation ei = new ExtendedInformation();
    	ei.setMaxLoginAttempts(7);
    	profile.doesUserFulfillEndEntityProfile("username","password","CN=John Smith","","","",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
    	                                         false,false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei, certProfileEndUser, null);

        log.trace("<maxFailedLogins");
    }

    /**
     * Tests checks for allowed CAs.
     */
    @Test
    public void limitedAvailableCAs() throws Exception {
        log.trace(">limitedAvailableCAs");
        final EndEntityProfile profile = new EndEntityProfile();
        
        // Set so CN=modifyable required, OU0={DEP1_1,DEP1_2} required, OU1={DEP2_1,DEP2_2} required, C=OU1={SE,DK} not required 
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.COUNTRY);
        
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,0,true);
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,1,true);
        
        profile.setModifyable(DnComponents.ORGANIZATIONALUNIT,0,false);
        profile.setModifyable(DnComponents.ORGANIZATIONALUNIT,1,false);
        profile.setModifyable(DnComponents.COUNTRY,0,false);
        
        profile.setValue(DnComponents.ORGANIZATIONALUNIT,0,"DEP1_1;DEP1_2");
        profile.setValue(DnComponents.ORGANIZATIONALUNIT,1,"DEP2_1;DEP2_2");
        profile.setValue(DnComponents.COUNTRY,0,"SE;DK");
        
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));

        // Test right CA
    	profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,null,"","test11@test.com",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, false,
    	                                         false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileSubCa, null);

        // Test Wrong CA
        try{ 
        	profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,null,"","test11@test.com",
        	                                         CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, false,
        	                                         false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_2, null, certProfileSubCa, null);
        	fail("Improper check of available ca's.");
        }catch(EndEntityProfileValidationException e){
        	assertEquals("Couldn't find CA (3) among End Entity Profiles Available CAs.", e.getMessage());
        }

        // Set Any CA available
        profile.setAvailableCAs(Collections.singletonList(SecConst.ALLCAS));

        // Test right CA
    	profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,null,"","test11@test.com",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, false,
    	                                         false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, null, certProfileSubCa, null);

        // Test Wrong CA
    	profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,null,"","test11@test.com",
    	                                         CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, false,
    	                                         false,false,SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_2, null, certProfileSubCa, null);
    	log.trace("<limitedAvailableCAs");
    }

    /**
     * Tests several attributes, amongst which e-mail is handled specially because the domain can be restricted without making the whole e-mail unmodifiable. 
     * <li>RFC 822 Name (e-mail)
     * <li>Organizational Unit
     * <li>Country
     * <li>UPN
     * <li>IP Address
     */
    @Test
    public void testProfileWithRfc822name() throws Exception {
        log.trace(">testProfileWithRfc822name");
        final EndEntityProfile profile = new EndEntityProfile();
        
        // Set so CN=modifyable required, OU0={DEP1_1,DEP1_2} required, OU1={DEP2_1,DEP2_2} required, C=OU1={SE,DK} not required 
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.COUNTRY);
        
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,0,true);
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT,1,true);
        
        profile.setModifyable(DnComponents.ORGANIZATIONALUNIT,0,false);
        profile.setModifyable(DnComponents.ORGANIZATIONALUNIT,1,false);
        profile.setModifyable(DnComponents.COUNTRY,0,false);
        
        profile.setValue(DnComponents.ORGANIZATIONALUNIT,0,"DEP1_1;DEP1_2");
        profile.setValue(DnComponents.ORGANIZATIONALUNIT,1,"DEP2_1;DEP2_2");
        profile.setValue(DnComponents.COUNTRY,0,"SE;DK");
        
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));
        
        profile.addField(DnComponents.DNSNAME);
        profile.addField(DnComponents.UPN);
        profile.addField(DnComponents.IPADDRESS);
        
        profile.setRequired(DnComponents.DNSNAME,0,true);
        profile.setRequired(DnComponents.UPN,0,true);
        profile.setRequired(DnComponents.IPADDRESS,0,true);
                
        profile.setModifyable(DnComponents.RFC822NAME,0,false);
        profile.setModifyable(DnComponents.DNSNAME,0,false);
        profile.setModifyable(DnComponents.UPN,0,false);
        profile.setModifyable(DnComponents.IPADDRESS,0,true);
        
        profile.setValue(DnComponents.DNSNAME,0,"test.primekey.se");
        profile.setValue(DnComponents.UPN,0,"test.com;primekey.se");
        profile.setValue(DnComponents.IPADDRESS,0,"11.11.1.1");

        profile.setEmailRequired(true);
        profile.setEmailModifiable(false);
        profile.setEmailDomain("test.com;primekey.se");
        
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
        profile.setValue(DnComponents.RFC822NAME,2,"test@somefoo.com");
        profile.setValue(DnComponents.RFC822NAME,3,"somebar.com");
        // Make sure normal usage works
        profile.doesUserFulfillEndEntityProfile("username","password",STANDARD_DN,
                "rfc822name=test@test.com, rfc822name=test@anything.com, rfc822name=test@somefoo.com, "+
                "dnsname=test.primekey.se, Upn=test12@primekey.se, ipaddress=11.11.1.2","","test@test.com",
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false,false,SecConst.TOKEN_SOFT_BROWSERGEN,
                TEST_CA_1, null, certProfileEndUser, null);
        log.trace("<testProfileWithRfc822name");
    }
    
    @Rule
    public ExpectedException expectedException = ExpectedException.none();
    
    /**
     * Test that if Cab Forum Organization Identifier is set to be Used in CP but not in EEP and it is
     * present in the extended information an end entity profile validation exception must be thrown 
     * with the appropriate message. 
     * 
     * @throws EndEntityProfileValidationException
     */
    @Test
    public void testCabFOrganizationIdentifierNotSetInEEP() throws EndEntityProfileValidationException {
        log.trace(">testCabFOrganizationIdentifierNotSetInEEP");
        
        expectedException.expect(EndEntityProfileValidationException.class);
        expectedException.expectMessage("CA/B Forum Organization Identifier is not set to Use in end entity profile but is present in extended information.");

        final EndEntityProfile profile = new EndEntityProfile();
        profile.setCabfOrganizationIdentifierUsed(false);
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));

        final ExtendedInformation ei = new ExtendedInformation();
        ei.setCabfOrganizationIdentifier(SAMPLECABFORGANICATIONID);
        
        final CertificateProfile certProfileEndUserWithCabFOIdUse = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProfileEndUserWithCabFOIdUse.setUseCabfOrganizationIdentifier(true);
        profile.doesUserFulfillEndEntityProfile("username", "password", "CN=John Smith", "", "", "",
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei,
                certProfileEndUserWithCabFOIdUse, null);
        log.trace("<testCabFOrganizationIdentifierNotSetInEEP");
    }
    
    /**
     * Tests that if Cab Forum Organization Identifier is set to be Used in CP and also in EEP and it is
     * present in the extended information test should go through without any errors. 
     * 
     * @throws Exception
     */
    @Test
    public void testCabFOrganizationIdentifierSetInEEP() throws Exception {
        log.trace(">testCabFOrganizationIdentifierSetInEEP");

        final EndEntityProfile profile = new EndEntityProfile();
        profile.setCabfOrganizationIdentifierUsed(true);
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));

        final ExtendedInformation ei = new ExtendedInformation();
        ei.setCabfOrganizationIdentifier(SAMPLECABFORGANICATIONID);
        
        final CertificateProfile certProfileEndUserWithCabFOIdUse = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProfileEndUserWithCabFOIdUse.setUseCabfOrganizationIdentifier(true);
        profile.doesUserFulfillEndEntityProfile("username", "password", "CN=John Smith", "", "", "",
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei,
                certProfileEndUserWithCabFOIdUse, null);
        log.trace("<testCabFOrganizationIdentifierSetInEEP");
    }
    
    @Test
    public void testCabFOrganizationIdentifierSetInEEPButNotInRequest() throws Exception {
        log.trace(">testCabFOrganizationIdentifierSetInEEPButNotInRequest");

        expectedException.expect(EndEntityProfileValidationException.class);
        expectedException.expectMessage("CA/B Forum Organization Identifier is set to Use in end entity profile but is not present in extended information and no predifined value for it set in end entity profile.");

        
        final EndEntityProfile profile = new EndEntityProfile();
        profile.setCabfOrganizationIdentifierUsed(true);
        profile.setCabfOrganizationIdentifierRequired(true);
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));

        final ExtendedInformation ei = new ExtendedInformation();

        
        final CertificateProfile certProfileEndUserWithCabFOIdUse = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProfileEndUserWithCabFOIdUse.setUseCabfOrganizationIdentifier(true);
        profile.doesUserFulfillEndEntityProfile("username", "password", "CN=John Smith", "", "", "",
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei,
                certProfileEndUserWithCabFOIdUse, null);
        
        log.trace("<testCabFOrganizationIdentifierSetInEEPButNotInRequest");

    }
    
    
    @Test
    public void testCabFOrganizationIdentifierSetInEEPWithPredefinedValueButNotInRequest() throws Exception {
        log.trace(">testCabFOrganizationIdentifierSetInEEPWithPredefinedValueButNotInRequest");
        
        final EndEntityProfile profile = new EndEntityProfile();
        profile.setCabfOrganizationIdentifierUsed(true);
        profile.setCabfOrganizationIdentifierRequired(true);
        profile.setCabfOrganizationIdentifier(SAMPLECABFORGANICATIONID);
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));

        final ExtendedInformation ei = new ExtendedInformation();
        
        final CertificateProfile certProfileEndUserWithCabFOIdUse = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProfileEndUserWithCabFOIdUse.setUseCabfOrganizationIdentifier(true);
        profile.doesUserFulfillEndEntityProfile("username", "password", "CN=John Smith", "", "", "",
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei,
                certProfileEndUserWithCabFOIdUse, null);
        
        log.trace("<testCabFOrganizationIdentifierSetInEEPWithPredefinedValueButNotInRequest");

    }

    @Test
    public void testInvalidEndEntityUsernameShouldThrowException() throws EndEntityProfileValidationException {
        expectedException.expect(EndEntityProfileValidationException.class);
        expectedException.expectMessage("Did not pass validation of field Username. Technical details: Value \"invalid-username\" does not match regex \\d");

        final EndEntityProfile profile = new EndEntityProfile();
        profile.setUseValidationForUsername(true);
        profile.setUsernameDefaultValidation("\\d");

        final CertificateProfile certProfileEndUserWithCabFOIdUse = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProfileEndUserWithCabFOIdUse.setUseCabfOrganizationIdentifier(true);

        profile.doesUserFulfillEndEntityProfile("invalid-username", "password", "CN=John Smith",
                                                "", "", "", CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                                                false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1,
                                                new ExtendedInformation(), certProfileEndUserWithCabFOIdUse, null);
    }

    @Test
    public void testValidEndEntityUsername() throws EndEntityProfileValidationException {
        final EndEntityProfile profile = new EndEntityProfile();
        profile.setUseValidationForUsername(true);
        profile.setUsernameDefaultValidation("[a-z]+");
        profile.setCabfOrganizationIdentifierUsed(true);
        profile.setCabfOrganizationIdentifierRequired(true);
        profile.setCabfOrganizationIdentifier(SAMPLECABFORGANICATIONID);
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));

        final CertificateProfile certProfileEndUserWithCabFOIdUse = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProfileEndUserWithCabFOIdUse.setUseCabfOrganizationIdentifier(true);

        profile.doesUserFulfillEndEntityProfile("username", "password", "CN=John Smith",
                                                "", "", "", CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                                                false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1,
                                                new ExtendedInformation(), certProfileEndUserWithCabFOIdUse, null);
    }

    @Test
    public void testEABInEEwithNotDefinedEabInCP() throws Exception {
        log.trace(">testEABInEEwithNotDefinedEabInCP");

        final EndEntityProfile profile = new EndEntityProfile();
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));
        final ExtendedInformation ei = new ExtendedInformation();
        ei.setAccountBindingId("AccountBindingId");

        profile.doesUserFulfillEndEntityProfile("username", "password", "CN=John Smith", "", "", "",
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1, ei,
                certProfileEndUser, null);
        log.trace("<testEABInEEwithNotDefinedEabInCP");
    }

    @Test
    public void testEABNotSetInEEDefinedInCP() throws EndEntityProfileValidationException {
        log.trace(">testEABNotSetInEEDefinedInCP");

        expectedException.expect(EndEntityProfileValidationException.class);
        expectedException.expectMessage("Certificate profile requires an External account ID");

        final EndEntityProfile profile = new EndEntityProfile();
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));

        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Set<String> namespaces = new HashSet<>(Collections.singletonList("EABNamespace"));
        certificateProfile.setEabNamespaces(namespaces);
        profile.doesUserFulfillEndEntityProfile("username", "password", "CN=John Smith", "", "", "",
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1,
                null, certificateProfile, null);
        log.trace("<testEABNotSetInEEDefinedInCP");
    }

    @Test
    public void testEABInEENamespaceNotInConfigs() throws EndEntityProfileValidationException {
        log.trace(">testEABInEENamespaceNotInConfigs");

        expectedException.expect(EndEntityProfileValidationException.class);
        expectedException.expectMessage("Account bindings namespace in Certificate profile is outdated (not present in System Configurations)");

        final EndEntityProfile profile = new EndEntityProfile();
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));
        ExtendedInformation ei = new ExtendedInformation();
        ei.setAccountBindingId("AccountBindingId");

        EABConfiguration eabConfiguration = new EABConfiguration();
        LinkedHashMap<String, Set<String>> map = new LinkedHashMap<>();
        map.put("Namespace1", new LinkedHashSet<>());
        map.put("Namespace2", new LinkedHashSet<>());
        eabConfiguration.setEabConfigMap(map);

        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Set<String> namespaces = new HashSet<>(Collections.singletonList("EABNamespace"));
        certificateProfile.setEabNamespaces(namespaces);
        profile.doesUserFulfillEndEntityProfile("username", "password", "CN=John Smith", "", "", "",
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1,
                ei, certificateProfile, eabConfiguration);
        log.trace("<testEABInEENamespaceNotInConfigs");
    }

    @Test
    public void testEABInEEAccountIdNotInConfigs() throws EndEntityProfileValidationException {
        log.trace(">testEABInEENamespaceNotInConfigs");

        expectedException.expect(EndEntityProfileValidationException.class);
        expectedException.expectMessage("External account ID is not in the list of allowed account ids");

        final EndEntityProfile profile = new EndEntityProfile();
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));
        ExtendedInformation ei = new ExtendedInformation();
        ei.setAccountBindingId("AccountBindingId");

        EABConfiguration eabConfiguration = new EABConfiguration();
        LinkedHashMap<String, Set<String>> map = new LinkedHashMap<>();
        final String eabNamespace = "Namespace1";
        map.put(eabNamespace, new LinkedHashSet<>());
        map.get(eabNamespace).add("SomeId");
        map.put("Namespace2", new LinkedHashSet<>());
        eabConfiguration.setEabConfigMap(map);

        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Set<String> namespaces = new HashSet<>(Collections.singletonList(eabNamespace));
        certificateProfile.setEabNamespaces(namespaces);
        profile.doesUserFulfillEndEntityProfile("username", "password", "CN=John Smith", "", "", "",
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1,
                ei, certificateProfile, eabConfiguration);
        log.trace("<testEABInEENamespaceNotInConfigs");
    }

    @Test
    public void testEABInEEAccountIdInConfigs() throws EndEntityProfileValidationException {
        log.trace(">testEABInEENamespaceNotInConfigs");
        final String accountBindingId = "AccountBindingId";
        final String eabNamespace = "Namespace1";

        final EndEntityProfile profile = new EndEntityProfile();
        profile.setAvailableCAs(Collections.singletonList(TEST_CA_1));
        ExtendedInformation ei = new ExtendedInformation();
        ei.setAccountBindingId(accountBindingId);

        EABConfiguration eabConfiguration = new EABConfiguration();
        LinkedHashMap<String, Set<String>> map = new LinkedHashMap<>();
        final LinkedHashSet<String> set = new LinkedHashSet<>();
        set.add(accountBindingId);
        map.put(eabNamespace, set);
        map.put("Namespace2", new LinkedHashSet<>());
        eabConfiguration.setEabConfigMap(map);

        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Set<String> namespaces = new HashSet<>(Collections.singletonList(eabNamespace));
        certificateProfile.setEabNamespaces(namespaces);
        profile.doesUserFulfillEndEntityProfile("username", "password", "CN=John Smith", "", "", "",
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, false, false, false, SecConst.TOKEN_SOFT_BROWSERGEN, TEST_CA_1,
                ei, certificateProfile, eabConfiguration);
        log.trace("<testEABInEENamespaceNotInConfigs");
    }
} 
