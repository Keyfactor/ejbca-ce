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

package org.ejbca.webtest.scenario;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.SearchEndEntitiesHelper;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa91_EndEntityNameConstraints extends WebTestBase {
    
    private static final Logger log = Logger.getLogger(EcaQa91_EndEntityNameConstraints.class);
    
    private static final AuthenticationToken admin = 
            new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertificateNameConstraintTest"));

    //Classes
    private static WebDriver webDriver;
    private static AddEndEntityHelper addEndEntityHelper;
    private static SearchEndEntitiesHelper searchEndEntitiesHelper;
    
    private static final String REPLACABLE_TAG = "$TAG$";
    
    private static final String TEST_NC_END_ENTITY_NAME = "testNCEndEntity" + REPLACABLE_TAG;
        
    private static final String TEST_NC_CERT_PROFILE_EE = "testNCEECertProfile";
    private static final String TEST_NC_EE_PROFILE_NAME = "testNCEndEntityProfile";
    
    private static final String HTML_NAME_TEXT_AREA_NC_PERMITTED = "textarencpermitted";
    private static final String HTML_NAME_TEXT_AREA_NC_EXCLUDED = "textarencexcluded";
    private static final String HTML_NAME_CHECKBOX_NC_PERMITTED = "checkboxrequiredncpermitted";
    private static final String HTML_NAME_CHECKBOX_NC_EXCLUDED = "checkboxrequiredncexcluded";
    
    private static List<String> nameConstPermitted, nameConstExcluded;
    private static String nameConstPermittedStr, nameConstExcludedStr;
    
    private static int endEntityCertificateProfileId;
    private static int endEntityProfileId;
    
    private static EndEntityProfile endEntityProfile;
    private static List<String> createdUsers;
    
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final CertificateProfileSessionRemote certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);

    
    @BeforeClass
    public static void init() throws Exception {
        beforeClass(true, null);
        webDriver = getWebDriver();
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
        searchEndEntitiesHelper = new SearchEndEntitiesHelper(webDriver);
        
        CryptoProviderTools.installBCProvider();
        
        nameConstPermitted = new ArrayList<String>();
        //nameConstPermitted.add("C=SE,O=PrimeKey,CN=example.com");
        nameConstPermitted.add("exampleinc.com");
        nameConstPermitted.add("@mail.example");
        nameConstPermitted.add("user@host.com");
        nameConstPermitted.add("10.0.0.0/8");
        nameConstPermitted.add("2001:db8::/32");
        //nameConstPermitted.add("C=SE,  CN=spacing");
        nameConstPermittedStr = nameConstPermitted.toString().replace(", ", "\n").substring(1);
        nameConstPermittedStr = nameConstPermittedStr.substring(0, nameConstPermittedStr.length()-1);
        nameConstPermittedStr = nameConstPermittedStr.replace("::/32", ":0:0:0:0:0:0/32");
        
        nameConstExcluded = new ArrayList<String>();
        nameConstExcluded.add("forbidden.example.com");
        nameConstExcluded.add("postmaster@mail.example");
        nameConstExcluded.add("10.1.0.0/16");
        nameConstExcluded.add("2005:ac7::/64");
        nameConstExcluded.add("C=SE,O=PrimeKey,CN=example.com");
        nameConstExcludedStr = nameConstExcluded.toString().replace(", ", "\n").substring(1);
        nameConstExcludedStr = nameConstExcludedStr.substring(0, nameConstExcludedStr.length()-1);
        nameConstExcludedStr = nameConstExcludedStr.replace("::/64", ":0:0:0:0:0:0/64");
        
        createdUsers = new ArrayList<String>();
        
        // ee cert profile 
        CertificateProfile endEntityCertprofile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        endEntityCertprofile.setUseNameConstraints(true);
        endEntityCertprofile.setUseLdapDnOrder(false);
        endEntityCertificateProfileId = certProfileSession.addCertificateProfile(admin, TEST_NC_CERT_PROFILE_EE, endEntityCertprofile);
        log.info("created end entity certificate profile id: " + endEntityCertificateProfileId);
        
        // end entity profile 
        endEntityProfile = new EndEntityProfile();
        endEntityProfile.setNameConstraintsPermittedUsed(true);
        endEntityProfile.setNameConstraintsPermittedRequired(false);
        endEntityProfile.setNameConstraintsExcludedUsed(true);
        endEntityProfile.setNameConstraintsExcludedRequired(false);
        List<Integer> availableCertProfiles = endEntityProfile.getAvailableCertificateProfileIds();
        availableCertProfiles.add(endEntityCertificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(availableCertProfiles);
        endEntityProfile.setAvailableCAs(Arrays.asList(new Integer[]{SecConst.ALLCAS}));
        
        endEntityProfileId = endEntityProfileSession.addEndEntityProfile(admin, TEST_NC_EE_PROFILE_NAME, endEntityProfile);
        log.info("Created end entity profile id: " + endEntityProfileId);
        
    }

    @AfterClass
    public static void exit() throws Exception {
        
        // remove all created users
        for(String username : createdUsers)
            endEntityManagementSession.deleteUser(admin, username);
        
        certProfileSession.removeCertificateProfile(admin, TEST_NC_CERT_PROFILE_EE);
        endEntityProfileSession.removeEndEntityProfile(admin, TEST_NC_EE_PROFILE_NAME);
        afterClass();
    }
    
    private String getRandomizedName(String nameTemplate) {
        Random r = new Random();
        return nameTemplate.replace(REPLACABLE_TAG, 1000 + r.nextInt(8999) + "");
    }
    
    private void editEndEntityProfile(boolean enablePermittedNC, boolean enableExcludedNC, 
            boolean requirePermittedNC, boolean requireExcludedNC) throws Exception {
        
        endEntityProfile.setNameConstraintsPermittedUsed(enablePermittedNC);
        endEntityProfile.setNameConstraintsPermittedRequired(requirePermittedNC);
        endEntityProfile.setNameConstraintsExcludedUsed(enableExcludedNC);
        endEntityProfile.setNameConstraintsExcludedRequired(requireExcludedNC);
        endEntityProfileSession.changeEndEntityProfile(admin, TEST_NC_EE_PROFILE_NAME, endEntityProfile);

        EndEntityProfile eeProfile = endEntityProfileSession.getEndEntityProfile(TEST_NC_EE_PROFILE_NAME);
        Assert.assertEquals(enablePermittedNC, eeProfile.isNameConstraintsPermittedUsed());
        Assert.assertEquals(enableExcludedNC, eeProfile.isNameConstraintsExcludedUsed());
        Assert.assertEquals(requirePermittedNC, eeProfile.isNameConstraintsPermittedRequired());
        Assert.assertEquals(requireExcludedNC, eeProfile.isNameConstraintsExcludedRequired());
    }
    
    private void addAndVerifyEndEntity(boolean enablePermittedNC, boolean enableExcludedNC, 
            boolean populatePermittedNC, boolean populateExcludedNC, 
            boolean requirePermittedNC, boolean requireExcludedNC) throws Exception {
        addAndVerifyEndEntity(enablePermittedNC, enableExcludedNC, populatePermittedNC, populateExcludedNC,
                        requirePermittedNC, requireExcludedNC, false);
    }
    
    private void addAndVerifyEndEntity(boolean enabledPermittedNC, boolean enabledExcludedNC, 
            boolean populatePermittedNC, boolean populateExcludedNC, 
            boolean requiredPermittedNC, boolean requiredExcludedNC, boolean expectionOnEECreation
            ) throws Exception {
        
        String endEntityName = getRandomizedName(TEST_NC_END_ENTITY_NAME);
        
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile(TEST_NC_EE_PROFILE_NAME);
        addEndEntityHelper.setCertificateProfile(TEST_NC_CERT_PROFILE_EE);
        addEndEntityHelper.setCa("ManagementCA");
        
        Map<String, String> userDetails = new HashMap<String, String>();
        userDetails.put("Username", endEntityName);
        userDetails.put("Password (or Enrollment Code)", endEntityName);
        userDetails.put("Confirm Password", endEntityName);
        userDetails.put("CN, Common name", endEntityName);
        addEndEntityHelper.fillFields(userDetails);
        
        WebElement permittedNCTextArea = null , excludedNCTextArea = null, 
                            permittedNCRequirredCheckbox = null, excludedNCRequirredCheckbox = null;
        boolean badELementFound = false;
        
        if(enabledPermittedNC) {
            try {
                permittedNCTextArea = webDriver.findElement(By.name(HTML_NAME_TEXT_AREA_NC_PERMITTED));
                if(populatePermittedNC)
                    permittedNCTextArea.sendKeys(nameConstPermittedStr);
            } catch (Exception e) {
                Assert.fail("Permitted name constraint area not visible.");
            }
            
            permittedNCRequirredCheckbox = webDriver.findElement(By.name(HTML_NAME_CHECKBOX_NC_PERMITTED));
            Assert.assertEquals("Permitted name constraint requirred checkbox is disabled or not selected.",
                                        requiredPermittedNC, permittedNCRequirredCheckbox.isSelected());
        } else {
            badELementFound = webDriver.findElements(By.name(HTML_NAME_TEXT_AREA_NC_PERMITTED)).size() == 0;
            Assert.assertTrue("Permitted name constraint area not visible when disabled at end entity profile.", 
                        badELementFound);
        }
        
        if(enabledExcludedNC) {
            try {
                excludedNCTextArea = webDriver.findElement(By.name(HTML_NAME_TEXT_AREA_NC_EXCLUDED));
                if(populateExcludedNC)
                    excludedNCTextArea.sendKeys(nameConstExcludedStr);
            } catch (Exception e) {
                Assert.fail("Excluded name constraint area not visible.");
            }
            
            excludedNCRequirredCheckbox = webDriver.findElement(By.name(HTML_NAME_CHECKBOX_NC_EXCLUDED));
            Assert.assertEquals("Excluded name constraint requirred checkbox is disabled or not selected.",
                                        requiredExcludedNC, excludedNCRequirredCheckbox.isSelected());
        } else {
            badELementFound = webDriver.findElements(By.name(HTML_NAME_CHECKBOX_NC_EXCLUDED)).size() == 0;
            Assert.assertTrue("Excluded name constraint area not visible when disabled at end entity profile.", 
                        badELementFound);
        }
        
        addEndEntityHelper.addEndEntity();
        try {
            Alert alert = webDriver.switchTo().alert();
            String alertText = alert.getText();
            alert.accept();
            
            if(requiredPermittedNC)
                Assert.assertTrue("Required permitted name constraint is not validated.", alertText.contains("permitted"));
            
            if(requiredExcludedNC)
                Assert.assertTrue("Required excluded name constraint is not validated.", alertText.contains("excluded"));
            
            return;
        } catch (Exception e) {
            if(expectionOnEECreation)
                Assert.fail("End entity created without required name constraints.");
        }
        createdUsers.add(endEntityName);
        
        searchEndEntitiesHelper.openPage(getAdminWebUrl());
        searchEndEntitiesHelper.fillSearchCriteria(endEntityName, null, null, null);
        searchEndEntitiesHelper.clickSearchByUsernameButton();
        searchEndEntitiesHelper.clickEditEndEntityForRow(endEntityName);
        String mainWindow = webDriver.getWindowHandle();
        searchEndEntitiesHelper.switchToPopup();
        
        if(enabledPermittedNC) {
            try {
                permittedNCTextArea = webDriver.findElement(By.name(HTML_NAME_TEXT_AREA_NC_PERMITTED));
                if(populatePermittedNC)
                    Assert.assertEquals("Permitted name constraints do not match.", 
                        permittedNCTextArea.getText(), nameConstPermittedStr);
                else
                    Assert.assertEquals("Permitted name constraints do not match.", 
                            permittedNCTextArea.getText(), "");
            } catch (Exception e) {
                Assert.fail("Permitted name constraint area not visible in edit view.");
            }
        } else {
            badELementFound = webDriver.findElements(By.name(HTML_NAME_TEXT_AREA_NC_PERMITTED)).size() == 0;
            Assert.assertTrue("Permitted name constraint area not visible "
                    + "when disabled at end entity profile in edit view.", badELementFound);
        }
        
        if(enabledExcludedNC) {
            try {
                excludedNCTextArea = webDriver.findElement(By.name(HTML_NAME_TEXT_AREA_NC_EXCLUDED));
                if(populateExcludedNC)
                    Assert.assertEquals("Excluded name constraints do not match.", 
                            excludedNCTextArea.getText(), nameConstExcludedStr);
                else
                    Assert.assertEquals("Excluded name constraints do not match.", 
                            excludedNCTextArea.getText(), "");
            } catch (Exception e) {
                Assert.fail("Excluded name constraint area not visible in edit view.");
            }
        } else {
            badELementFound = webDriver.findElements(By.name(HTML_NAME_CHECKBOX_NC_EXCLUDED)).size() == 0;
            Assert.assertTrue("Excluded name constraint area not visible "
                    + "when disabled at end entity profile in edit view.", badELementFound);
        }
        
        webDriver.close();
        webDriver.switchTo().window(mainWindow);
        
    }
    
    @Test
    public void testA_AddEndEntityPermittedAndExcluded() throws Exception { 
        addAndVerifyEndEntity(true, true, true, true, false, false);
    }
    
    @Test
    public void testB_AddEndEntityPermittedOnly() throws Exception {
        addAndVerifyEndEntity(true, true, true, false, false, false);
    }
    
    @Test
    public void testC_AddEndEntityExcludededOnly() throws Exception {
        addAndVerifyEndEntity(true, true, false, true, false, false);
    }
    
    @Test
    public void testD_AddEndEntityWithoutNameConstraint() throws Exception {
        addAndVerifyEndEntity(true, true, false, false, false, false);
    }
    
    @Test
    public void testE_UpdateEEProfileToOnlyPermitted() throws Exception {
        editEndEntityProfile(true, false, false, false);
    }
    
    @Test
    public void testF_AddEndEntityPermittedOnly() throws Exception {
        addAndVerifyEndEntity(true, false, true, false, false, false);
    }
    
    @Test
    public void testG_UpdateEEProfileToOnlyExcluded() throws Exception {
        editEndEntityProfile(false, true, false, false);
    }
    
    @Test
    public void testH_AddEndEntityExcludedOnly() throws Exception {
        addAndVerifyEndEntity(false, true, false, true, false, false);
    }
    
    @Test
    public void testI_UpdateEEProfileToNoNameConstraint() throws Exception {
        editEndEntityProfile(false, false, false, false);
    }
    
    @Test
    public void testJ_AddEndEntityWONameConstraint() throws Exception {
        addAndVerifyEndEntity(false, false, false, false, false, false);
    }
    
    @Test
    public void testK_UpdateEEProfileToPermittedNCRequirred() throws Exception {
        editEndEntityProfile(true, true, true, false);
    }
    
    @Test
    public void testL_AddEndEntityPermittedOnly() throws Exception {
        addAndVerifyEndEntity(true, true, true, false, true, false);
    }
    
    @Test
    public void testM_AddEndEntityWONameConstraintNegative() throws Exception {
        addAndVerifyEndEntity(true, true, false, false, true, false, true);
    }
    
    @Test
    public void testN_UpdateEEProfileToExcludedNCRequirred() throws Exception {
        editEndEntityProfile(true, true, false, true);
    }
    
    @Test
    public void testO_AddEndEntityExcludedOnly() throws Exception {
        addAndVerifyEndEntity(true, true, false, true, false, true);
    }
    
    @Test
    public void testP_AddEndEntityWONameConstraintNegative() throws Exception {
        addAndVerifyEndEntity(true, true, false, false, false, true, true);
    }
    
    
}
