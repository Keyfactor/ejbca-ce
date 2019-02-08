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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.filefilter.WildcardFileFilter;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.AuditLogHelper;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.SearchEndEntitiesHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * Creates a CA and an End Entity and checks that the actions are logged properly.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa76_AuditLogSearch extends WebTestBase {

    private static WebDriver webDriver;
    // Helpers
    private static CaHelper caHelper;
    private static AuditLogHelper auditLogHelper;
    private static SearchEndEntitiesHelper searchEndEntitiesHelper;
    private static AddEndEntityHelper addEndEntityHelper;
    
    // Test Data
    private static class TestData {
        private static final Map<String, String> ADD_EE_FIELDMAP = new HashMap<>();
        static final String CA_NAME = "TestAuditLog";
        static final String CN_CHANGED = "testchangevalue";
        static final String EE_NAME = "testauditlog";

        static {
            ADD_EE_FIELDMAP.put("Username", EE_NAME);
            ADD_EE_FIELDMAP.put("Password (or Enrollment Code)", "foo123");
            ADD_EE_FIELDMAP.put("Confirm Password", "foo123");
            ADD_EE_FIELDMAP.put("CN, Common name", "testauditlog");
        }
    }
    private static final String deleteAlert = "Are you sure you want to delete the CA " + TestData.CA_NAME + "? You should revoke the CA instead if you already have used it to issue certificates.";

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        cleanup(); // clean up data from aborted test runs
        webDriver = getWebDriver();
        // Init helpers
        caHelper = new CaHelper(webDriver);
        auditLogHelper = new AuditLogHelper(webDriver);
        searchEndEntitiesHelper = new SearchEndEntitiesHelper(webDriver);
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        cleanup();
        // super
        afterClass();
    }

    /**
     * Removes generated artifacts
     */
    private static void cleanup() {
        removeEndEntityByUsername(TestData.EE_NAME);
        removeCaAndCryptoToken(TestData.CA_NAME);
    }

    @Test
    public void stepA_addCa() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        // Add CA and check that it was added successfully
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity("40y");
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
        // Select the CA, click 'Delete CA' and then 'Cancel'
        caHelper.deleteCaAndAssert(deleteAlert, false, null, TestData.CA_NAME);
    }

   @Test
    public void stepB_addEe() {
       // Add End Entity
       addEndEntityHelper.openPage(getAdminWebUrl());
       addEndEntityHelper.setEndEntityProfile("EMPTY");
       addEndEntityHelper.fillFields(TestData.ADD_EE_FIELDMAP);
       addEndEntityHelper.setCertificateProfile("ENDUSER");
       addEndEntityHelper.setCa(getCaName());
       addEndEntityHelper.setToken("User Generated");
       addEndEntityHelper.addEndEntity();
       
    }

    @Test
    public void stepC_editEe() {
        String mainWindow = webDriver.getWindowHandle();
        String editWindow = null;

        // Click 'Edit' in 'Previously added end entities' table
        webDriver.findElement(By.xpath("(//table[@class='results']//tr)[2]//button[text()='Edit']")).click();
        Set<String> handles = webDriver.getWindowHandles();
        for (String handle : handles) {
            if (!handle.equals(mainWindow)) {
                editWindow = handle;
                break;
            }
        }

        // Set a new CN and click 'Save' at the bottom
        webDriver.switchTo().window(editWindow);
        WebElement cnInput = webDriver.findElement(By.xpath("//td[descendant-or-self::*[text()='CN, Common name']]/following-sibling::td//input[not(@type='checkbox')]"));
        cnInput.clear();
        cnInput.sendKeys(TestData.CN_CHANGED);
        webDriver.findElement(By.xpath("(//input[@name='buttonedituser'])[2]")).click();
        assertEquals("Unexpected save message upon edit of End Entitys", "End Entity Saved", webDriver.findElement(By.xpath("//div[@class='message info']")).getText());
        webDriver.close();
        webDriver.switchTo().window(mainWindow);
    }

    @Test
    public void stepD_allEvents() {
        // Check that the correct events exist in the Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "End Entity Edit",
                "Success",
                null,
                Arrays.asList(
                        "msg=Edited end entity " + TestData.ADD_EE_FIELDMAP.get("Username"),
                        "subjectDN=CN=" + TestData.ADD_EE_FIELDMAP.get("CN, Common name") + " -> CN=" + TestData.CN_CHANGED)
        );
        auditLogHelper.assertLogEntryByEventText(
                "End Entity Add",
                "Success",
                null,
                Collections.singletonList("msg=Added end entity " + TestData.ADD_EE_FIELDMAP.get("Username"))
        );
        auditLogHelper.assertLogEntryByEventText(
                "CRL Create",
                "Success",
                null,
                Collections.singletonList("CA 'TestAuditLog' with DN 'CN=TestAuditLog'")
        );
        auditLogHelper.assertLogEntryByEventText(
                "CRL Store",
                "Success",
                null,
                Collections.singletonList("issuerDN 'CN=" + TestData.CA_NAME + "'")
        );
        auditLogHelper.assertLogEntryByEventText(
                "Certificate Store",
                "Success",
                null,
                Collections.singletonList("subjectDN 'CN=" + TestData.CA_NAME + "', issuerDN 'CN=" + TestData.CA_NAME + "'")
        );
        auditLogHelper.assertLogEntryByEventText(
                "CA Edit",
                "Success",
                null,
                Collections.singletonList("name " + TestData.CA_NAME + " edited")
        );
        auditLogHelper.assertLogEntryByEventText(
                "CA Create",
                "Success",
                null,
                Collections.singletonList("name " + TestData.CA_NAME + " added")
        );
    }

    @Test
    public void stepE_eeEvents() {
        // Add condition and check that the correct entries are displayed
        auditLogHelper.setViewFilteringCondition("Username", "Equals", TestData.ADD_EE_FIELDMAP.get("Username"));
        assertEquals("Unexpected number of entries in the Audit Log", 2, AuditLogHelper.entryCount(webDriver));
        assertEquals("Unexpected element found in table", "End Entity Edit",
                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[1]/td[2]")).getText());
        assertEquals("Unexpected element found in table", "End Entity Add",
                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[2]/td[2]")).getText());

        // Click the down arrow in the 'Event' column and check that the order of the elements are changed
        webDriver.findElement(By.xpath("(//input[@class='sortButton'])[3]")).click();
        assertEquals("Unexpected number of entries in the Audit Log", 2, AuditLogHelper.entryCount(webDriver));
        assertEquals("Unexpected element found in table", "End Entity Add",
                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[1]/td[2]")).getText());
        assertEquals("Unexpected element found in table", "End Entity Edit",
                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[2]/td[2]")).getText());

        // Click the up arrow in the 'Event' column and check that the order of the elements are changed back
        webDriver.findElement(By.xpath("(//input[@class='sortButton'])[4]")).click();
        assertEquals("Unexpected number of entries in the Audit Log", 2, AuditLogHelper.entryCount(webDriver));
        assertEquals("Unexpected element found in table", "End Entity Edit",
                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[1]/td[2]")).getText());
        assertEquals("Unexpected element found in table", "End Entity Add",
                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[2]/td[2]")).getText());
    }

    @Test
    public void stepF_clear() {
        // Click remove for 'Access Control' and make sure it's deleted
        webDriver.findElement(By.xpath("//td[text()='Access Control']/following-sibling::td/input")).click();
        try {
            webDriver.findElement(By.xpath("//td[text()='Access Control']"));
            fail("The rule 'Access Control' was still present after removal");
        } catch (NoSuchElementException e) {}

        // Check that the Audit Log still looks the same
        assertEquals("Unexpected number of entries in the Audit Log", 2, AuditLogHelper.entryCount(webDriver));
        assertEquals("Unexpected element found in table", "End Entity Edit",
                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[1]/td[2]")).getText());
        assertEquals("Unexpected element found in table", "End Entity Add",
                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[2]/td[2]")).getText());

        // Clear all conditions, sort by Module and check that there are only Access Control rules listed
        auditLogHelper.clearConditions();
        webDriver.findElement(By.xpath("(//input[@class='sortButton'])[9]")).click();
        assertEquals("Expected only 'Access Control' events in the Audit Log", AuditLogHelper.entryCount(webDriver),
                webDriver.findElements(By.xpath("//tr/td[2][text()='Access Control']")).size());
    }

    @Test
    public void stepG_download() throws IOException {
        // Reset the conditions
        auditLogHelper.openPage(getAdminWebUrl());
        // Sort by time and set 'Displaying results' and 'Entries per page'
        webDriver.findElement(By.xpath("(//input[@class='sortButton'])[2]")).click();
        auditLogHelper.setViewPaginationProperties(2, 5);
        auditLogHelper.reloadView();

        // Check that the Audit Log has the expected look
        assertEquals("Unexpected number of entries in the Audit Log", 5, AuditLogHelper.entryCount(webDriver));
        assertEquals("Unexpected element found in table", "End Entity Add",
                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[1]/td[2]")).getText());
        assertEquals("Unexpected element found in table", "CRL Create",
                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[2]/td[2]")).getText());
        assertEquals("Unexpected element found in table", "CRL Store",
                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[3]/td[2]")).getText());
        assertEquals("Unexpected element found in table", "Certificate Store",
                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[4]/td[2]")).getText());
        assertEquals("Unexpected element found in table", "CA Edit",
                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[5]/td[2]")).getText());

        // Click 'Download shown results', this will automatically download the XML file
        webDriver.findElement(By.xpath("//input[contains(@value, 'Download shown results') and not(contains(@value, 'CMS'))]")).click();

        // Get all XML files in folder matching the file name pattern and sort by last modified (newest first)
        List<File> xmlFiles = Arrays.asList((new File(getDownloadDir())).listFiles((FileFilter) new WildcardFileFilter("export-*.xml")));
        Collections.sort(xmlFiles, new Comparator<File>() {
            @Override
            public int compare(File first, File second) {
                if (first.lastModified() == second.lastModified()) {
                    return 0;
                } else {
                    return first.lastModified() > second.lastModified() ? -1 : 1;
                }
            }
        });
        String results = new String(Files.readAllBytes(Paths.get(xmlFiles.get(0).getAbsolutePath())));
        assertTrue("Results did not contain expected contents", results.contains("<string>" + TestData.ADD_EE_FIELDMAP.get("Username") + "</string>"));
        assertTrue("Results did not contain expected contents", results.contains("&lt;string&gt;Added end entity " + TestData.ADD_EE_FIELDMAP.get("Username") + ".&lt;/string&gt;"));
    }

    @Test
    public void stepH_search() {
        searchEndEntitiesHelper.openPage(getAdminWebUrl());
        searchEndEntitiesHelper.switchViewModeFromAdvancedToBasic();
        // Search for End Entity, make sure there is exactly 1 result
        searchEndEntitiesHelper.fillSearchCriteria(TestData.ADD_EE_FIELDMAP.get("Username"), null, null, null);
        searchEndEntitiesHelper.clickSearchByUsernameButton();
        searchEndEntitiesHelper.assertNumberOfSearchResults(1);

    }
}