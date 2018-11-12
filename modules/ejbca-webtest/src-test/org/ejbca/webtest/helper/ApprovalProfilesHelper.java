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
package org.ejbca.webtest.helper;

import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

// TODO Actual implementation and refactoring take place in ECA-7356
/**
 * Helper class for handling 'Approval Profiles' page in automated web tests.
 *
 * @version $Id: ApprovalProfilesHelper.java 30446 2018-11-09 10:16:38Z andrey_s_helmes $
 */
public class ApprovalProfilesHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'Approval Profiles' page.
     */
    public static class Page {

    }

    public ApprovalProfilesHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    // TODO Refactor ECA-7356 - EcaQa87_ApprovalMgmtPartition
    public void addApprovalProfile(final String adminWebUrl, final String approvalProfileName, final String roleName, final String roleName2) {
        webDriver.get(adminWebUrl);
        //By.xpath("//a[contains(@href,'/ejbca/adminweb/approval/editapprovalprofiles.xhtml')]"));
        WebElement approvalProfilesLink = webDriver.findElement(By.id("supervisionEditapprovalprofiles"));
        approvalProfilesLink.click();
        // Dynamically rendered items require some special handling...
        WebElement inputName = webDriver.findElement(By.xpath("//input[contains(@name,'editapprovalprofiles:j_id') and //input[@type='text']]"));
        inputName.sendKeys(approvalProfileName);
        WebElement addProfile = webDriver.findElement(By.xpath("//input[contains(@name,'editapprovalprofiles:j_id') and //input[@value='Add']]"));
        addProfile.sendKeys(Keys.RETURN);

        WebElement addedItemRow = webDriver.findElement(By.xpath("//tbody/tr/td[contains(text(), '" + approvalProfileName + "')]"));
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

        verifySteps(steps, roleName, roleName2);
    }

    // TODO Refactor ECA-7356 - EcaQa153_ApprovalRoleSettings
    public void addApprovalProfile(final String adminWebUrl, final String approvalProfileName, final String roleName) {
        webDriver.get(adminWebUrl);
        // By.xpath("//a[contains(@href,'/ejbca/adminweb/approval/editapprovalprofiles.xhtml')]")
        WebElement approvalProfilesLink = webDriver.findElement(By.id("supervisionEditapprovalprofiles"));
        approvalProfilesLink.click();
        // Dynamically rendered items require some special handling...
        WebElement inputName = webDriver.findElement(By.xpath("//input[contains(@name,'editapprovalprofiles:j_id') and //input[@type='text']]"));
        inputName.sendKeys(approvalProfileName);
        WebElement addProfile = webDriver.findElement(By.xpath("//input[contains(@name,'editapprovalprofiles:j_id') and //input[@value='Add']]"));
        addProfile.sendKeys(Keys.RETURN);

        WebElement addedItemRow = webDriver.findElement(By.xpath("//tbody/tr/td[contains(text(), '" + approvalProfileName + "')]"));
        WebElement addedItemEditButton = addedItemRow.findElement(By.xpath("../td[@class='gridColumn2']/div/input[@value='Edit']"));
        addedItemEditButton.sendKeys(Keys.RETURN);

        Select dropDownProfileType =  new Select(webDriver.findElement(By.id("approvalProfilesForm:selectOneMenuApprovalType")));
        dropDownProfileType.selectByValue("PARTITIONED_APPROVAL");
        List<WebElement> stepAdmins = webDriver.findElements(By.xpath("//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:j_id')]"));
        for (WebElement box : stepAdmins) {
            Select selectAdmin = new Select(box);
            selectAdmin.deselectAll();
            selectAdmin.selectByVisibleText(roleName);
//            selectOptionByName(box, roleName);
        }
        WebElement saveButton =  webDriver.findElement(By.xpath("//td[@class='editColumn2']/span/input[contains(@name,'approvalProfilesForm:j_id') and //input[@value='Save']]"));
        saveButton.sendKeys(Keys.RETURN);
        verifyApprovalsViewMode(adminWebUrl, approvalProfileName, roleName);
    }

    // TODO Refactor ECA-7356 - EcaQa87_ApprovalMgmtPartition
    // Requires browser to be at /ejbca/adminweb/approval/editapprovalprofile.xhtml using 'Partitioned Approvals'
    public void verifySteps(List<WebElement> steps, final String roleName, final String roleName2) {
        for (WebElement step : steps) {
            //Verify present elements
            try {
                step.findElement(By.xpath(".//input[@value='Add Partition']"));
                step.findElement(By.xpath(".//input[@value='Delete Step']"));
            } catch (NoSuchElementException e) {
                fail("Could not locate expected element: " + e.getMessage());
            }
            List<WebElement> partitions = step.findElements(By.xpath(".//table[@class='subTable']"));
            verifyPartitions(partitions, roleName, roleName2);
        }
    }

    // TODO Refactor ECA-7356 - EcaQa87_ApprovalMgmtPartition
    // Requires browser to be at /ejbca/adminweb/approval/editapprovalprofile.xhtml using 'Partitioned Approvals'
    public void verifyPartitions(List<WebElement> partitions, final String roleName, final String roleName2) {
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

    // TODO Refactor ECA-7356 - EcaQa87_ApprovalMgmtPartition
    public void addStep(final String roleName, final String roleName2) {
        // Add a new step
        webDriver.findElement(By.xpath("//input[@value='Add Step']")).click();
        WebElement superTable = webDriver.findElement(By.xpath("//table[@class='superTable']"));
        List<WebElement> steps = superTable.findElements(By.xpath("./tbody/tr/td"));
        assertEquals("Unexpected number of initial steps", 2, steps.size());
        verifySteps(steps, roleName, roleName2);
    }

    // TODO Refactor ECA-7356 - EcaQa87_ApprovalMgmtPartition
    public void addPartition(final String roleName, final String roleName2) {
        WebElement superTable = webDriver.findElement(By.xpath("//table[@class='superTable']"));
        List<WebElement> steps = superTable.findElements(By.xpath("./tbody/tr/td"));
        // Add partition to step 1 and update main table
        steps.get(0).findElement(By.xpath(".//input[@value='Add Partition']")).click();
        superTable = webDriver.findElement(By.xpath("//table[@class='superTable']"));
        steps = superTable.findElements(By.xpath("./tbody/tr/td"));

        List<WebElement> partitions = steps.get(0).findElements(By.xpath(".//table[@class='subTable']"));
        assertEquals("Unexpected number of partitions in step 1 after adding an extra partition", 2, partitions.size());

        // Verify content of both partitions again
        verifyPartitions(partitions, roleName, roleName2);
    }

    // TODO Refactor ECA-7356 - EcaQa87_ApprovalMgmtPartition
    public void addField() {
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

    // TODO Refactor ECA-7356 - EcaQa87_ApprovalMgmtPartition
    public void addNamesAndAdmins(final String roleName, final String roleName2) {
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

    // TODO Refactor ECA-7356 - EcaQa87_ApprovalMgmtPartition
    public void saveAndVerify(final String roleName, final String roleName2) {
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

    // TODO Refactor ECA-7356 - EcaQa153_ApprovalRoleSettings
    public void verifyApprovalsViewMode(final String adminWebUrl, final String approvalProfileName, final String roleName) {
        webDriver.get(adminWebUrl);
        // By.xpath("//a[contains(@href,'/ejbca/adminweb/approval/editapprovalprofiles.xhtml')]")
        WebElement approvalProfilesLink = webDriver.findElement(By.id("supervisionEditapprovalprofiles"));
        approvalProfilesLink.click();

        WebElement addedItemRowPostEdit = webDriver.findElement(By.xpath("//tbody/tr/td[contains(text(), '" + approvalProfileName + "')]"));
        WebElement addedItemViewButton = addedItemRowPostEdit.findElement(By.xpath("../td[@class='gridColumn2']/div/input[@value='View']"));
        addedItemViewButton.sendKeys(Keys.RETURN);

        List<WebElement> stepAdminsViewMode = webDriver.findElements(By.xpath("//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:j_id')]"));
        for (WebElement box : stepAdminsViewMode) {
            Select selectAdmin = new Select(box);
            assertEquals("Roles authorized to view and approve partition was not saved / visible in 'View mode'", roleName, selectAdmin.getFirstSelectedOption().getText());
        }
    }

}
