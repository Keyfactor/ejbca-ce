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

package org.ejbca.webtest;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.WebTestBase;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

/**
 * 
 * @version $Id$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa87_ApprovalMgmtPartition  extends WebTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));
    private static final String roleName = "AdminRole1";
    private static final String roleName2 = "AdminRole2";
    private static final String approvalProfileName = "Partitioned Profile";
    private static final String caName = "TestApprovalCA";
    private static final String cpName = "TestApprovalCertificateProfile";
    
    private static WebDriver webDriver;
    private static RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private static ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
    private static CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static CertificateProfileSessionRemote cpSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    
    
    
    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }
    
    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        Role role1 = roleSession.getRole(admin, null, roleName);
        if (role1 != null) {
            roleSession.deleteRoleIdempotent(admin, role1.getRoleId());
        }
        Role role2 = roleSession.getRole(admin, null, roleName2);
        if (role2 != null) {
            roleSession.deleteRoleIdempotent(admin, role2.getRoleId());
        }
        CAInfo caInfo = caSession.getCAInfo(admin, caName);
        if (caInfo != null) {
            caSession.removeCA(admin, caInfo.getCAId());
        }
        cpSession.removeCertificateProfile(admin, cpName);
        Map<Integer, String> approvalIdNameMap = approvalProfileSession.getApprovalProfileIdToNameMap();
        for (Entry<Integer, String> approvalProfile : approvalIdNameMap.entrySet()) {
            if (approvalProfile.getValue().equals(approvalProfileName)) {
                approvalProfileSession.removeApprovalProfile(admin, approvalProfile.getKey());
            }
        }
        webDriver.quit();
    }
    
    // Requires browser to be at page ejbca/adminweb/administratorprivileges/roles.xhtml 
    private void addRoleSuperAdmin(String roleName) throws AuthorizationDeniedException {
        webDriver.findElement(By.id("roles:list:j_idt134")).click();
        webDriver.findElement(By.xpath("//input[@name='modal:j_idt150']")).sendKeys(roleName);
        webDriver.findElement(By.id("modal:j_idt154")).click();
        
        WebElement infoMessage = webDriver.findElement(By.xpath("//li[@class='infoMessage']"));
        assertEquals("Unexpected info message while adding role","Role added." , infoMessage.getText());
        
        int roleId = roleSession.getRole(admin, null, roleName).getRoleId();
        String findRoleTableRow = "//a[@href='accessrules.xhtml?roleId=" + roleId + "']";
        webDriver.findElement(By.xpath(findRoleTableRow)).click();
        
        Select roleTemplate = new Select(webDriver.findElement(By.id("accessRulesForm:selectrole")));
        roleTemplate.selectByValue("SUPERADMINISTRATOR");
        webDriver.findElement(By.id("accessRulesForm:j_idt156")).click();
        
        infoMessage = webDriver.findElement(By.xpath("//li[@class='infoMessage']"));
        assertEquals("Unexpected info message while adding role","Role updated successfully." , infoMessage.getText());
    }

    @Test
    public void testA_createRoles() throws AuthorizationDeniedException {
        webDriver.get(getAdminWebUrl());
        WebElement adminRolesLink = webDriver.findElement(By.xpath("//a[contains(@href,'ejbca/adminweb/administratorprivileges/roles.xhtml')]"));
        adminRolesLink.click();
        
        addRoleSuperAdmin(roleName);
        webDriver.findElement(By.xpath("//a[@href='roles.xhtml']")).click();
        addRoleSuperAdmin(roleName2);
    }

    @Test
    public void testB_addApprovalProfile() {
        webDriver.get(getAdminWebUrl());
        WebElement approvalProfilesLink = webDriver.findElement(By.xpath("//a[contains(@href,'/ejbca/adminweb/approval/editapprovalprofiles.jsf')]"));
        approvalProfilesLink.click();
        // Dynamically rendered items require some special handling...
        WebElement inputName = webDriver.findElement(By.xpath("//input[contains(@name,'editapprovalprofiles:j_id') and //input[@type='text']]"));
        inputName.sendKeys(approvalProfileName);
        WebElement addProfile = webDriver.findElement(By.xpath("//input[contains(@name,'editapprovalprofiles:j_id') and //input[@value='Add']]"));
        addProfile.sendKeys(Keys.RETURN);
        
        WebElement addedItemRow = webDriver.findElement(By.xpath("//tbody/tr/td[contains(text(), 'Partitioned Profile')]"));
        WebElement addedItemEditButton = addedItemRow.findElement(By.xpath("../td[@class='gridColumn2']/div/input[@value='Edit']"));
        addedItemEditButton.sendKeys(Keys.RETURN);
        
        Select dropDownProfileType =  new Select(webDriver.findElement(By.id("approvalProfilesForm:selectOneMenuApprovalType")));
        dropDownProfileType.selectByValue("PARTITIONED_APPROVAL");
        WebElement reqExpPeriod = webDriver.findElement(By.id("approvalProfilesForm:reqExpPeriod"));
        reqExpPeriod.clear();
        reqExpPeriod.sendKeys("7h 43m 20s");
        WebElement approvalExpPeriod = webDriver.findElement(By.id("approvalProfilesForm:approvalExpPeriod"));
        approvalExpPeriod.clear();
        approvalExpPeriod.sendKeys("8h 16m 40s");
        
        //Verify present elements
        try {
            webDriver.findElement(By.xpath("//input[@value='Add Step']"));
            webDriver.findElement(By.xpath("//input[@value='Save']"));
            webDriver.findElement(By.xpath("//input[@value='Cancel']"));
        } catch (NoSuchElementException e) {
            fail("Could not locate expected element: " + e.getMessage());
        }
        
        WebElement superTable = webDriver.findElement(By.xpath("//table[@class='superTable']"));
        List<WebElement> steps = superTable.findElements(By.xpath("./tbody/tr/td"));
        assertEquals("Unexpected number of initial steps", 1, steps.size());
        verifySteps(steps);
    }

    @Test
    public void testC_addStep() {
        // Add a new step
        webDriver.findElement(By.xpath("//input[@value='Add Step']")).click();
        
        WebElement superTable = webDriver.findElement(By.xpath("//table[@class='superTable']"));
        List<WebElement> steps = superTable.findElements(By.xpath("./tbody/tr/td"));
        assertEquals("Unexpected number of initial steps", 2, steps.size());
        verifySteps(steps);

    }

    @Test
    public void testD_addPartition() {
        WebElement superTable = webDriver.findElement(By.xpath("//table[@class='superTable']"));
        List<WebElement> steps = superTable.findElements(By.xpath("./tbody/tr/td"));
        // Add partition to step 1 and update main table
        steps.get(0).findElement(By.xpath(".//input[@value='Add Partition']")).click();
        superTable = webDriver.findElement(By.xpath("//table[@class='superTable']"));
        steps = superTable.findElements(By.xpath("./tbody/tr/td"));
        
        List<WebElement> partitions = steps.get(0).findElements(By.xpath(".//table[@class='subTable']"));
        assertEquals("Unexpected number of partitions in step 1 after adding an extra partition", 2, partitions.size());
        
        // Verify content of both partitions again
        verifyPartitions(partitions);
    }

    @Test
    public void testE_addFields() {
        WebElement superTable = webDriver.findElement(By.xpath("//table[@class='superTable']"));
        List<WebElement> steps = superTable.findElements(By.xpath("./tbody/tr/td"));
        List<WebElement> stepOnePartitions = steps.get(0).findElements(By.xpath(".//table[@class='subTable']"));
        List<WebElement> stepTwoPartitions = steps.get(1).findElements(By.xpath(".//table[@class='subTable']"));
        
        Select stepOnePartitionOneFields = new Select(stepOnePartitions.get(0).findElement(
                By.xpath(".//td[@class='tableFooter-approval-step']/table/tbody/tr/td/select[contains(@name,'approvalProfilesForm:j_id')]")));
        stepOnePartitionOneFields.selectByValue("CHECKBOX");
        stepOnePartitions.get(0).findElement(By.xpath(".//input[@value='Add Field']")).click();
        
        superTable = webDriver.findElement(By.xpath("//table[@class='superTable']"));
        steps = superTable.findElements(By.xpath("./tbody/tr/td"));
        stepOnePartitions = steps.get(0).findElements(By.xpath(".//table[@class='subTable']"));
        Select stepOnePartitionTwoFields = new Select(stepOnePartitions.get(1).findElement(
                By.xpath(".//td[@class='tableFooter-approval-step']/table/tbody/tr/td/select[contains(@name,'approvalProfilesForm:j_id')]")));
        stepOnePartitionTwoFields.selectByValue("RADIOBUTTON");
        stepOnePartitions.get(1).findElement(By.xpath(".//input[@value='Add Field']")).click();
        
        WebElement radioButtonHolder = webDriver.findElement(By.xpath("//span[contains(text(), 'Radio Button Label:')]/input[@type='text']"));
        radioButtonHolder.sendKeys("Label1");
        webDriver.findElement(By.xpath("//span[contains(text(), 'Radio Button Label:')]/input[@type='submit']")).click();
        
        radioButtonHolder = webDriver.findElement(By.xpath("//span[contains(text(), 'Radio Button Label:')]/input[@type='text']"));
        radioButtonHolder.clear();
        radioButtonHolder.sendKeys("Label2");
        webDriver.findElement(By.xpath("//span[contains(text(), 'Radio Button Label:')]/input[@type='submit']")).click();
        
        superTable = webDriver.findElement(By.xpath("//table[@class='superTable']"));
        steps = superTable.findElements(By.xpath("./tbody/tr/td"));
        stepTwoPartitions = steps.get(1).findElements(By.xpath(".//table[@class='subTable']"));
        Select stepTwoPartitionOneFields = new Select(stepTwoPartitions.get(0).findElement(
                By.xpath(".//td[@class='tableFooter-approval-step']/table/tbody/tr/td/select[contains(@name,'approvalProfilesForm:j_id')]")));
        stepTwoPartitionOneFields.selectByValue("INTEGER");
        stepTwoPartitions.get(0).findElement(By.xpath(".//input[@value='Add Field']")).click();
        
        // Update DOM and verify outcome of adding fields
        superTable = webDriver.findElement(By.xpath("//table[@class='superTable']"));
        steps = superTable.findElements(By.xpath("./tbody/tr/td"));
        stepOnePartitions = steps.get(0).findElements(By.xpath(".//table[@class='subTable']"));
        stepTwoPartitions = steps.get(1).findElements(By.xpath(".//table[@class='subTable']"));
        try {
            stepOnePartitions.get(0).findElement(By.xpath(".//input[@type='checkbox']"));
            List<WebElement> radioButtons = stepOnePartitions.get(1).findElements(By.xpath(".//input[@type='radio']"));
            assertEquals("Could not find all added radio buttons", 2, radioButtons.size());
            stepTwoPartitions.get(0).findElement(By.xpath(".//input[@value='0']"));
        } catch (NoSuchElementException e) {
            fail("Failed to locate added field: " + e.getMessage());
        }
    }

    @Test
    public void testF_addNamesAndAdmins() {
        WebElement superTable = webDriver.findElement(By.xpath("//table[@class='superTable']"));
        List<WebElement> steps = superTable.findElements(By.xpath("./tbody/tr/td"));
        List<WebElement> stepOnePartitions = steps.get(0).findElements(By.xpath(".//table[@class='subTable']"));
        List<WebElement> stepTwoPartitions = steps.get(1).findElements(By.xpath(".//table[@class='subTable']"));

        stepOnePartitions.get(0).findElement(By.xpath(".//td[@class='editColumn2-Approval-steps']/input[contains(@type,'text')]")).sendKeys("1:A");
        stepOnePartitions.get(1).findElement(By.xpath(".//td[@class='editColumn2-Approval-steps']/input[contains(@type,'text')]")).sendKeys("1:B");
        stepTwoPartitions.get(0).findElement(By.xpath(".//td[@class='editColumn2-Approval-steps']/input[contains(@type,'text')]")).sendKeys("2:A");
        
        for (WebElement adminSelect : superTable.findElements(By.xpath(".//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:j_id')]"))) {
            new Select(adminSelect).deselectAll();
        }
        
        List<WebElement> stepOnePartOneAdminSelect = stepOnePartitions.get(0).findElements(By.xpath(".//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:j_id')]"));
        new Select(stepOnePartOneAdminSelect.get(0)).selectByVisibleText(roleName);
        new Select(stepOnePartOneAdminSelect.get(1)).selectByVisibleText("Anybody");
        List<WebElement> stepOnePartTwoAdminSelect = stepOnePartitions.get(1).findElements(By.xpath(".//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:j_id')]"));
        new Select(stepOnePartTwoAdminSelect.get(0)).selectByVisibleText(roleName2);
        new Select(stepOnePartTwoAdminSelect.get(1)).selectByVisibleText("Anybody");
        List<WebElement> stepTwoPartOneAdminSelect = stepTwoPartitions.get(0).findElements(By.xpath(".//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:j_id')]"));
        new Select(stepTwoPartOneAdminSelect.get(0)).selectByVisibleText(roleName);
        new Select(stepTwoPartOneAdminSelect.get(1)).selectByVisibleText("Anybody");
    }

    @Test
    public void testG_saveAndVerify() {
        webDriver.findElement(By.xpath("//input[@value='Save']")).click();
        WebElement editedItemRow = webDriver.findElement(By.xpath("//tbody/tr/td[contains(text(), 'Partitioned Profile')]"));
        WebElement addedItemViewButton = editedItemRow.findElement(By.xpath("../td[@class='gridColumn2']/div/input[@value='View']"));
        addedItemViewButton.sendKeys(Keys.RETURN);
        
        Select dropDownProfileType =  new Select(webDriver.findElement(By.id("approvalProfilesForm:selectOneMenuApprovalType")));
        assertEquals("Partitioned Approval was not selected after save", "PARTITIONED_APPROVAL", dropDownProfileType.getFirstSelectedOption().getAttribute("value"));
        assertEquals("Unexpected Request Expiration Period", "7h 43m 20s", webDriver.findElement(By.id("approvalProfilesForm:reqExpPeriod")).getAttribute("value"));
        assertEquals("Unexpected Approval Expiration Period", "8h 16m 40s", webDriver.findElement(By.id("approvalProfilesForm:approvalExpPeriod")).getAttribute("value"));
        
        //Verify present elements
        try {
            webDriver.findElement(By.xpath("//input[@value='Add Step']"));
            webDriver.findElement(By.xpath("//input[@value='Save']"));
            webDriver.findElement(By.xpath("//input[@value='Cancel']"));
            fail("'Add Step', 'Save' or 'Cancel button was present in view mode'");
        } catch (NoSuchElementException e) {} //Expected
       
        try {
            webDriver.findElement(By.xpath("//input[@value='Back']"));
        } catch (NoSuchElementException e) {
            fail("'Back' button was not present in view mode");
        }
        
        List<WebElement> buttons = webDriver.findElements(By.xpath("//input[@type='submit']"));
        for (WebElement button : buttons) {
            if (!button.getAttribute("value").equals("Back")) {
                assertEquals("Button was not disabled in view mode", "true", button.getAttribute("disabled"));
            }
        }
        
        List<WebElement> fields = webDriver.findElements(By.xpath("//input[@type='text']"));
        for (WebElement field : fields) {
            assertEquals("Field was not disabled in view mode", "true", field.getAttribute("disabled"));
        }
        
        WebElement superTable = webDriver.findElement(By.xpath("//table[@class='superTable']"));
        List<WebElement> steps = superTable.findElements(By.xpath("./tbody/tr/td"));
        List<WebElement> stepOnePartitions = steps.get(0).findElements(By.xpath(".//table[@class='subTable']"));
        List<WebElement> stepTwoPartitions = steps.get(1).findElements(By.xpath(".//table[@class='subTable']"));
        
        assertEquals("Unexpected partition name in view mode", "1:A", stepOnePartitions.get(0).
                findElement(By.xpath(".//td[@class='editColumn2-Approval-steps']/input[contains(@type,'text')]")).getAttribute("value"));
        assertEquals("Unexpected partition name in view mode", "1:B", stepOnePartitions.get(1).
                findElement(By.xpath(".//td[@class='editColumn2-Approval-steps']/input[contains(@type,'text')]")).getAttribute("value"));
        assertEquals("Unexpected partition name in view mode", "2:A", stepTwoPartitions.get(0).
                findElement(By.xpath(".//td[@class='editColumn2-Approval-steps']/input[contains(@type,'text')]")).getAttribute("value"));
        
        List<WebElement> stepOnePartOneRoles = stepOnePartitions.get(0).findElements(By.xpath(".//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:j_id')]"));
        List<WebElement> stepOnePartTwoRoles = stepOnePartitions.get(1).findElements(By.xpath(".//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:j_id')]"));
        List<WebElement> stepTwoPartOneRoles = stepTwoPartitions.get(0).findElements(By.xpath(".//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:j_id')]"));
        
        assertEquals("Step 1, Partition 1: Unexpected number of selected 'May Approve' admins", 1, new Select(stepOnePartOneRoles.get(0)).getAllSelectedOptions().size());
        assertEquals("Step 1, Partition 1: Unexpected number of selected 'May View' admins", 1, new Select(stepOnePartOneRoles.get(1)).getAllSelectedOptions().size());
        assertEquals("Step 1, Partition 1: Unexpected selected 'May Approve' admin", roleName, new Select(stepOnePartOneRoles.get(0)).getFirstSelectedOption().getText());
        assertEquals("Step 1, Partition 1: Unexpected selected 'May View' admin", "Anybody", new Select(stepOnePartOneRoles.get(1)).getFirstSelectedOption().getText());
        
        assertEquals("Step 1, Partition 2: Unexpected number of selected 'May Approve' admins", 1, new Select(stepOnePartTwoRoles.get(0)).getAllSelectedOptions().size());
        assertEquals("Step 1, Partition 2: Unexpected number of selected 'May View' admins", 1, new Select(stepOnePartTwoRoles.get(1)).getAllSelectedOptions().size());
        assertEquals("Step 1, Partition 2: Unexpected selected 'May Approve' admin", roleName2, new Select(stepOnePartTwoRoles.get(0)).getFirstSelectedOption().getText());
        assertEquals("Step 1, Partition 2: Unexpected selected 'May View' admin", "Anybody", new Select(stepOnePartTwoRoles.get(1)).getFirstSelectedOption().getText());
        
        assertEquals("Step 2, Partition 1: Unexpected number of selected 'May Approve' admins", 1, new Select(stepTwoPartOneRoles.get(0)).getAllSelectedOptions().size());
        assertEquals("Step 2, Partition 1: Unexpected number of selected 'May View' admins", 1, new Select(stepTwoPartOneRoles.get(1)).getAllSelectedOptions().size());
        assertEquals("Step 2, Partition 1: Unexpected selected 'May Approve' admin", roleName, new Select(stepTwoPartOneRoles.get(0)).getFirstSelectedOption().getText());
        assertEquals("Step 2, Partition 1: Unexpected selected 'May View' admin", "Anybody", new Select(stepTwoPartOneRoles.get(1)).getFirstSelectedOption().getText());
        
//        selectedRolesOnly(stepOnePartOneRoles, Arrays.asList("Anybody", roleName));

    }

    @Test
    public void testH_createCa() {
        WebElement caLink = webDriver.findElement(By.xpath("//a[contains(@href,'/ejbca/adminweb/ca/editcas/editcas.jsp')]"));
        caLink.click();
        webDriver.findElement(By.xpath("//input[@name='textfieldcaname']")).sendKeys(caName);
        webDriver.findElement(By.xpath("//input[@name='buttoncreateca']")).click();
        webDriver.findElement(By.id("textfieldvalidity")).sendKeys("1y");
        List<WebElement> approvalDropDowns = webDriver.findElements(By.xpath("//select[contains(@name, 'approvalprofile_')]"));
        for (WebElement approvalDropDown : approvalDropDowns) {
            new Select(approvalDropDown).selectByVisibleText(approvalProfileName);
        }
        webDriver.findElement(By.xpath("//input[@name='buttoncreate']")).click();
    }
    
    @Test
    public void testI_createCp() {
        webDriver.get(getAdminWebUrl());
        WebElement cpLink = webDriver.findElement(By.xpath("//a[contains(@href,'/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.jsf')]"));
        cpLink.click();

        WebElement cpNameInput = webDriver.findElement(By.xpath("//input[@title='Identifier, string formated']"));
        cpNameInput.sendKeys(cpName);
        WebElement cpAddButton = webDriver.findElement(By.xpath("//input[@value='Add']"));
        cpAddButton.click();

        WebElement cpListTable = webDriver.findElement(By.id("editcertificateprofiles"));
        WebElement addedCpListItem = cpListTable.findElement(By.xpath(".//td[contains(text(), 'TestApprovalCertificateProfile')]"));
        assertTrue("Added certificate profile was not found in the list of Certificate Profiles", addedCpListItem.getText().equals(cpName));
        addedCpListItem.findElement(By.xpath("../td[@class='gridColumn2']/span/input[@value='Edit']")).click();
        
        List<WebElement> approvalDropDowns = webDriver.findElements(By.cssSelector("[id$=approvalProfile]"));
        for (WebElement approvalDropDown : approvalDropDowns) {
            new Select(approvalDropDown).selectByVisibleText(approvalProfileName);
        }
        
        webDriver.findElement(By.xpath("//input[@value='Save']")).click();
        
        //Verify View mode
        cpListTable = webDriver.findElement(By.id("editcertificateprofiles"));
        addedCpListItem = cpListTable.findElement(By.xpath(".//td[contains(text(), 'TestApprovalCertificateProfile')]"));
        assertTrue("Added certificate profile was not found in the list of Certificate Profiles", addedCpListItem.getText().equals(cpName));
        addedCpListItem.findElement(By.xpath("../td[@class='gridColumn2']/span/input[@value='View']")).click();
        
        approvalDropDowns = webDriver.findElements(By.cssSelector("[id$=approvalProfile]"));
        for (WebElement approvalDropDown : approvalDropDowns) {
            assertEquals("Selected approval profile was not selected in View mode", approvalProfileName, new Select(approvalDropDown).getFirstSelectedOption().getText());
        }
    }
    
    // Requires browser to be at /ejbca/adminweb/approval/editapprovalprofile.jsf using 'Partitioned Approvals'
    private void verifyPartitions(List<WebElement> partitions) {
        for (WebElement partition : partitions) {
            partition.findElement(By.xpath(".//input[@value='Add notification']"));
            partition.findElement(By.xpath(".//input[@value='Add user notification']"));
            partition.findElement(By.xpath(".//input[@value='Add Field']"));
            partition.findElement(By.xpath(".//input[contains(@name,'approvalProfilesForm:j_id') and //input[@type='text'] and //input[@value='']]"));
            WebElement deletePartitionButton = partition.findElement(By.xpath(".//input[@value='Delete Partition']"));
            if (partitions.size() > 1) {
                assertEquals("Delete partition was disabled when there were more than one partition present", null, deletePartitionButton.getAttribute("disabled"));
            } else {
                assertEquals("Delete partition was not disabled when there was only one partition present", "true", deletePartitionButton.getAttribute("disabled"));
            }
            List<WebElement> partitionAdmins = partition.findElements(By.xpath(".//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:j_id')]"));
            for (WebElement box : partitionAdmins) {
                Select selectAdmin = new Select(box);
                try {
                    selectAdmin.selectByVisibleText("Anybody");
                    selectAdmin.selectByVisibleText(roleName);
                    selectAdmin.selectByVisibleText(roleName2);
                } catch (NoSuchElementException e) {
                    fail("Expected roles not visible in 'Roles which may...' box: " + e.getMessage());
                }
            }
            
            List<WebElement> fieldDropDown = new Select(partition.findElement(
                    By.xpath(".//td[@class='tableFooter-approval-step']/table/tbody/tr/td/select[contains(@name,'approvalProfilesForm:j_id')]"))).getOptions();
            String[] expectedItems = {"Check Box", "Number (Short)", "Number (Long)", "Radio Button", "Text Field"};
            assertEquals("Unexpected number of dropdown items in 'Field' drop down", expectedItems.length, fieldDropDown.size());
            for (int i = 0; i < fieldDropDown.size(); i++) {
                assertEquals("Unexpected field drop down item in approval step", expectedItems[i], fieldDropDown.get(i).getText());
            }
        }
    }
    
 // Requires browser to be at /ejbca/adminweb/approval/editapprovalprofile.jsf using 'Partitioned Approvals'
    private void verifySteps(List<WebElement> steps) {
        for (WebElement step : steps) {
            //Verify present elements
            try {
                step.findElement(By.xpath(".//input[@value='Add Partition']"));
                step.findElement(By.xpath(".//input[@value='Delete Step']"));
            } catch (NoSuchElementException e) {
                fail("Could not locate expected element: " + e.getMessage());
            }
            List<WebElement> partitions = step.findElements(By.xpath(".//table[@class='subTable']"));
            verifyPartitions(partitions);
        }
    }
}
