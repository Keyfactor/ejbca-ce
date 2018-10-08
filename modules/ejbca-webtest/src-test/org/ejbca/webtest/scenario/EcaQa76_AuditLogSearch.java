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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.AuditLogHelper;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.WebTestHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

/**
 * Creates a CA and an End Entity and checks that the actions are logged properly.
 * 
 * @version $Id: EcaQa76_AuditLogSearch.java 30018 2018-10-04 15:31:01Z andrey_s_helmes $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa76_AuditLogSearch extends WebTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));

    private static WebDriver webDriver;
    private static CaSessionRemote caSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static CryptoTokenManagementSessionRemote cryptoTokenManagementSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);

    private static final String caName = "TestAuditLog";
    private static final String cnChanged = "testchangevalue";
    private static final String deleteAlert = "Are you sure you want to delete the CA " + caName + "? You should revoke the CA instead if you already have used it to issue certificates.";
    private static final Map<String,String> fieldMap = new HashMap<String, String>();
    static {
        fieldMap.put("Username", "testauditlog");
        fieldMap.put("Password (or Enrollment Code)", "foo123");
        fieldMap.put("Confirm Password", "foo123");
        fieldMap.put("CN, Common name", "testauditlog");
    }

    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException, NoSuchEndEntityException {
        int caId = caSessionRemote.getCAInfo(admin, caName).getCAId();
        int ctId = cryptoTokenManagementSessionRemote.getIdFromName(caName);
        caSessionRemote.removeCA(admin, caId);
        cryptoTokenManagementSessionRemote.deleteCryptoToken(admin, ctId);
        webDriver.quit();
    }

//    @Test
//    public void testA_addCa() {
//        AuditLogHelper.resetFilterTime();
//
//        // Add CA and check that it was added successfully
//        CaHelper.goTo(webDriver, getAdminWebUrl());
//        CaHelper.add(webDriver, caName);
//        CaHelper.setValidity(webDriver, "40y");
//        CaHelper.save(webDriver);
//        CaHelper.assertExists(webDriver, caName);
//
//        // Select the CA, click 'Delete CA' and then 'Cancel'
//        webDriver.findElement(By.xpath("//input[@name='buttondeleteca']")).click();
//        WebTestHelper.assertAlert(webDriver, deleteAlert, false);
//        CaHelper.assertExists(webDriver, caName);
//    }

//   @Test
//    public void testB_addEe() {
//        // Add End Entity
//        AddEndEntityHelper.goTo(webDriver, getAdminWebUrl());
//        AddEndEntityHelper.setEep(webDriver, "EMPTY");
//        AddEndEntityHelper.setFields(webDriver, fieldMap);
//        AddEndEntityHelper.setCp(webDriver, "ENDUSER");
//        AddEndEntityHelper.setCa(webDriver, getCaName());
//        AddEndEntityHelper.setToken(webDriver, "User Generated");
//        AddEndEntityHelper.save(webDriver, true);
//    }

//    @Test
//    public void testC_editEe() {
//        String mainWindow = webDriver.getWindowHandle();
//        String editWindow = null;
//
//        // Click 'Edit' in 'Previously added end entities' table
//        webDriver.findElement(By.xpath("(//table[@class='results']//tr)[2]//button[text()='Edit']")).click();
//        Set<String> handles = webDriver.getWindowHandles();
//        for (String handle : handles) {
//            if (!handle.equals(mainWindow)) {
//                editWindow = handle;
//                break;
//            }
//        }
//
//        // Set a new CN and click 'Save' at the bottom
//        webDriver.switchTo().window(editWindow);
//        WebElement cnInput = webDriver.findElement(By.xpath("//td[descendant-or-self::*[text()='CN, Common name']]/following-sibling::td//input[not(@type='checkbox')]"));
//        cnInput.clear();
//        cnInput.sendKeys(cnChanged);
//        webDriver.findElement(By.xpath("(//input[@name='buttonedituser'])[2]")).click();
//        assertEquals("Unexpected save message upon edit of End Entitys", "End Entity Saved", webDriver.findElement(By.xpath("//div[@class='message info']")).getText());
//        webDriver.close();
//        webDriver.switchTo().window(mainWindow);
//    }

//    @Test
//    public void testD_allEvents() {
//        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
//
//        // Check that the correct events exist in the Audit Log
//        AuditLogHelper.assertEntry(webDriver, "End Entity Edit", "Success", null,
//                Arrays.asList("msg=Edited end entity " + fieldMap.get("Username"), "subjectDN=CN=" + fieldMap.get("CN, Common name") + " -> CN=" + cnChanged));
//        AuditLogHelper.assertEntry(webDriver, "End Entity Add", "Success", null,
//                Arrays.asList("msg=Added end entity " + fieldMap.get("Username")));
//        AuditLogHelper.assertEntry(webDriver, "CRL Create", "Success", null,
//                Arrays.asList("CA 'TestAuditLog' with DN 'CN=TestAuditLog'"));
//        AuditLogHelper.assertEntry(webDriver, "CRL Store", "Success", null,
//                Arrays.asList("issuerDN 'CN=" + caName + "'"));
//        AuditLogHelper.assertEntry(webDriver, "Certificate Store", "Success", null,
//                Arrays.asList("subjectDN 'CN=" + caName + "', issuerDN 'CN=" + caName + "'"));
//        AuditLogHelper.assertEntry(webDriver, "CA Edit", "Success", null,
//                Arrays.asList("name " + caName + " edited"));
//        AuditLogHelper.assertEntry(webDriver, "CA Create", "Success", null,
//                Arrays.asList("name " + caName + " added"));
//    }

//    @Test
//    public void testE_eeEvents() {
//        // Add condition and check that the correct entries are displayed
//        AuditLogHelper.addCondition(webDriver, "Username", "Equals", fieldMap.get("Username"));
//        assertEquals("Unexpected number of entries in the Audit Log", 2, AuditLogHelper.entryCount(webDriver));
//        assertEquals("Unexpected element found in table", "End Entity Edit",
//                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[1]/td[2]")).getText());
//        assertEquals("Unexpected element found in table", "End Entity Add",
//                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[2]/td[2]")).getText());
//
//        // Click the down arrow in the 'Event' column and check that the order of the elements are changed
//        webDriver.findElement(By.xpath("(//input[@class='sortButton'])[3]")).click();
//        assertEquals("Unexpected number of entries in the Audit Log", 2, AuditLogHelper.entryCount(webDriver));
//        assertEquals("Unexpected element found in table", "End Entity Add",
//                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[1]/td[2]")).getText());
//        assertEquals("Unexpected element found in table", "End Entity Edit",
//                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[2]/td[2]")).getText());
//
//        // Click the up arrow in the 'Event' column and check that the order of the elements are changed back
//        webDriver.findElement(By.xpath("(//input[@class='sortButton'])[4]")).click();
//        assertEquals("Unexpected number of entries in the Audit Log", 2, AuditLogHelper.entryCount(webDriver));
//        assertEquals("Unexpected element found in table", "End Entity Edit",
//                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[1]/td[2]")).getText());
//        assertEquals("Unexpected element found in table", "End Entity Add",
//                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[2]/td[2]")).getText());
//    }

//    @Test
//    public void testF_clear() {
//        // Click remove for 'Access Control' and make sure it's deleted
//        webDriver.findElement(By.xpath("//td[text()='Access Control']/following-sibling::td/input")).click();
//        try {
//            webDriver.findElement(By.xpath("//td[text()='Access Control']"));
//            fail("The rule 'Access Control' was still present after removal");
//        } catch (NoSuchElementException e) {}
//
//        // Check that the Audit Log still looks the same
//        assertEquals("Unexpected number of entries in the Audit Log", 2, AuditLogHelper.entryCount(webDriver));
//        assertEquals("Unexpected element found in table", "End Entity Edit",
//                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[1]/td[2]")).getText());
//        assertEquals("Unexpected element found in table", "End Entity Add",
//                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[2]/td[2]")).getText());
//
//        // Clear all conditions, sort by Module and check that there are only Access Control rules listed
//        AuditLogHelper.clearConditions(webDriver);
//        webDriver.findElement(By.xpath("(//input[@class='sortButton'])[9]")).click();
//        assertEquals("Expected only 'Access Control' events in the Audit Log", AuditLogHelper.entryCount(webDriver),
//                webDriver.findElements(By.xpath("//tr/td[2][text()='Access Control']")).size());
//    }

//    @Test
//    public void testG_download() throws IOException {
//        // Reset the conditions
//        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
//
//        // Sort by time and set 'Displaying results' and 'Entries per page'
//        webDriver.findElement(By.xpath("(//input[@class='sortButton'])[2]")).click();
//        AuditLogHelper.setDisplayingResults(webDriver, 2);
//        AuditLogHelper.setEntriesPerPage(webDriver, 5);
//        AuditLogHelper.reload(webDriver);
//
//        // Check that the Audit Log has the expected look
//        assertEquals("Unexpected number of entries in the Audit Log", 5, AuditLogHelper.entryCount(webDriver));
//        assertEquals("Unexpected element found in table", "End Entity Add",
//                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[1]/td[2]")).getText());
//        assertEquals("Unexpected element found in table", "CRL Create",
//                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[2]/td[2]")).getText());
//        assertEquals("Unexpected element found in table", "CRL Store",
//                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[3]/td[2]")).getText());
//        assertEquals("Unexpected element found in table", "Certificate Store",
//                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[4]/td[2]")).getText());
//        assertEquals("Unexpected element found in table", "CA Edit",
//                webDriver.findElement(By.xpath("//table[caption[text()='Search results']]/tbody/tr[5]/td[2]")).getText());
//
//        // Click 'Download shown results', this will automatically download the XML file
//        webDriver.findElement(By.xpath("//input[contains(@value, 'Download shown results') and not(contains(@value, 'CMS'))]")).click();
//
//        // Get all XML files in folder matching the file name pattern and sort by last modified (newest first)
//        List<File> xmlFiles = Arrays.asList((new File(getDownloadDir())).listFiles((FileFilter) new WildcardFileFilter("export-*.xml")));
//        Collections.sort(xmlFiles, new Comparator<File>() {
//            @Override
//            public int compare(File first, File second) {
//                if (first.lastModified() == second.lastModified()) {
//                    return 0;
//                } else {
//                    return first.lastModified() > second.lastModified() ? -1 : 1;
//                }
//            }
//        });
//        String results = new String(Files.readAllBytes(Paths.get(xmlFiles.get(0).getAbsolutePath())));
//        assertTrue("Results did not contain expected contents", results.contains("<string>" + fieldMap.get("Username") + "</string>"));
//        assertTrue("Results did not contain expected contents", results.contains("&lt;string&gt;Added end entity " + fieldMap.get("Username") + ".&lt;/string&gt;"));
//    }

//    @Test
//    public void testH_search() throws IOException {
//        // Search for End Entity, make sure there is exactly 1 result
//        webDriver.findElement(By.xpath("//li/a[contains(@href,'listendentities.jsp')]")).click();
//        webDriver.findElement(By.xpath("//input[@name='textfieldusername']")).sendKeys(fieldMap.get("Username"));
//        webDriver.findElement(By.xpath("//input[@name='buttonfind']")).click();
//        assertEquals("Unexpected number of End Entity results on search", 1, webDriver.findElements(By.xpath("//table[@class='results']/tbody/tr")).size());
//
//        // Select the End Entity and delete
//        webDriver.findElement(By.xpath("//table[@class='results']/tbody/tr//input[@type='checkbox']")).click();
//        webDriver.findElement(By.xpath("//input[@name='buttondeleteusers']")).click();
//        WebTestHelper.assertAlert(webDriver, "Are you sure you want to delete selected end entities?", true);
//        WebTestHelper.assertAlert(webDriver, "Are the selected end entities revoked?", true);
//
//        // Make sure that there are no End Entities in the list (have to wait for reload)
//        WebDriverWait wait = new WebDriverWait(webDriver, 3);
//        wait.until(ExpectedConditions.visibilityOfElementLocated(By.xpath("//table[@class='results']/tbody//td[text()='No end entities found.']")));
//        assertEquals("Unexpected text in search table", "No end entities found.", webDriver.findElement(By.xpath("//table[@class='results']/tbody//td")).getText());
//    }
}