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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.WebTestHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * This test checks the behavior of EEP Notifications in the edit view.
 * 
 * @version $Id: EcaQa62_EepNotifications.java 29858 2018-09-11 07:44:14Z andrey_s_helmes $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa62_EepNotifications extends WebTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("UserDataTest"));

    private static WebDriver webDriver;
    private static EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    private static final String eepName = "NotificationEEP-ECAQA-62";
    private static final String firstText = "first";
    private static final String secondText = "second";
    private static final String thirdText = "third";

    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        endEntityProfileSession.removeEndEntityProfile(admin, eepName);
        webDriver.quit();
    }

//    @Test
//    public void a_addEep() {
//        EndEntityProfileHelper.goTo(webDriver, getAdminWebUrl());
//        EndEntityProfileHelper.add(webDriver, eepName, true);
//
//        // Verify that notifications are disabled by default
//        EndEntityProfileHelper.edit(webDriver, eepName);
//        assertFalse("'Send Notification' was checked upon creation of EEP", webDriver.findElement(By.id("checkboxusesendnotification")).isSelected());
//        try {
//            webDriver.findElement(By.xpath("//tr[td/strong[text()='Send Notification']]/following-sibling::tr[1]/td[2][contains(text(), 'Notification')]"));
//            fail("There were notifications displayed upon creation of EEP");
//        } catch (NoSuchElementException e) {}
//    }

//    // TODO Documentation has to be built before this case works
//    @Ignore
//    @Test
//    public void b_checkDocumentation() {
//        openDocumentation("//strong[text()='Send Notification']/following-sibling::a", "E-mail Notifications");
//    }

//    @Test
//    public void c_enableNotifications() {
//        // Check 'Use' and check that 'Default=', 'Required' and 'Add' are enabled (and not selected)
//        webDriver.findElement(By.id("checkboxusesendnotification")).click();
//        assertTrue("'Default=' was not enabled", webDriver.findElement(By.id("checkboxsendnotification")).isEnabled());
//        assertFalse("'Default=' was selected", webDriver.findElement(By.id("checkboxsendnotification")).isSelected());
//        assertTrue("'Required' was not enabled", webDriver.findElement(By.id("checkboxrequiredsendnotification")).isEnabled());
//        assertFalse("'Required' was selected", webDriver.findElement(By.id("checkboxrequiredsendnotification")).isSelected());
//        assertTrue("'Add' was not enabled", webDriver.findElement(By.xpath("//input[@name='buttonaddnotification']")).isEnabled());
//
//        // Click 'Add' button and check that all the fields are added
//        webDriver.findElement(By.xpath("//input[@name='buttonaddnotification']")).click();
//        try {
//            webDriver.findElement(By.xpath("//td[contains(text(), 'Notification Sender')]/following-sibling::td/input[@id='textfieldnotificationsender' and @type='text']"));
//            webDriver.findElement(By.xpath("//td[contains(text(), 'Notification Recipient')]/following-sibling::td/input[@name='textfieldnotificationrcpt' and @type='text']"));
//            webDriver.findElement(By.xpath("//td[contains(text(), 'Notification Events')]/following-sibling::td/select[@name='selectnotificationevents']"));
//            webDriver.findElement(By.xpath("//td[contains(text(), 'Notification Subject')]/following-sibling::td/input[@name='textfieldnotificationsubject' and @type='text']"));
//            webDriver.findElement(By.xpath("//td[contains(text(), 'Notification Message')]/following-sibling::td/textarea[@name='textareanotificationmessage']"));
//            webDriver.findElement(By.xpath("//input[@name='buttonaddanothernotification']"));
//            assertTrue("Cancel button was not enabled", webDriver.findElement(By.xpath("//input[@name='buttondeletetemporarynotification']")).isEnabled());
//        } catch (NoSuchElementException e) {
//            fail("All fields were not displayed correctly after adding notification");
//        }
//    }

//    // TODO Documentation has to be built before this case works
//    @Ignore
//    @Test
//    public void d_checkDocumentation() {
//        openDocumentation("//td[contains(text(), 'Notification Subject')]/a", "Dynamic Substitution Variables");
//        openDocumentation("//td[contains(text(), 'Notification Message')]/a", "Dynamic Substitution Variables");
//    }

//    @Test
//    public void e_addAnotherNotification() {
//        webDriver.findElement(By.xpath("//input[@name='buttonaddanothernotification']")).click();
//        WebTestHelper.assertAlert(webDriver, "You must fill in a notification sender if notification is to be used.", true);
//        WebTestHelper.assertAlert(webDriver, "You must fill in a notification subject if notification is to be used.", true);
//        WebTestHelper.assertAlert(webDriver, "You must fill in a notification message if notification is to be used.", true);
//
//        // Click 'Cancel' and make sure that the page looks like before
//        webDriver.findElement(By.xpath("//input[@name='buttondeletetemporarynotification']")).click();
//        try {
//            webDriver.findElement(By.xpath("//td[contains(text(), 'Notification Sender')]/following-sibling::td/input[@id='textfieldnotificationsender' and @type='text']"));
//            fail("'Notification Sender' still displayed");
//        } catch (NoSuchElementException e) {}
//        assertEquals("'Add' button doesn't display 'Add'", "Add", webDriver.findElement(By.xpath("//input[@name='buttonaddnotification']")).getAttribute("value"));
//    }

//    @Test
//    public void f_addFirstNotification() {
//        webDriver.findElement(By.xpath("//input[@name='buttonaddnotification']")).click();
//
//        // Fill fields with 'first' and then click 'Add Another'
//        fillTopPrototype(firstText);
//        webDriver.findElement(By.xpath("//input[@name='buttonaddanothernotification']")).click();
//
//        // Make sure the new prototype is on top
//        assertTrue("Top prototype was not empty", webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsender']")).getText().isEmpty());
//        assertEquals("Bottom prototype didn't contain expected value", firstText, webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsubject_newvalue0']")).getAttribute("value"));
//        assertEquals("Bottom prototype didn't have 'Delete' button", "Delete", webDriver.findElement(By.xpath("//input[@name='buttondeleltenotification0']")).getAttribute("value"));
//
//        // Click 'Save' and make sure the correct error messages are displayed
//        EndEntityProfileHelper.save(webDriver, false);
//        WebTestHelper.assertAlert(webDriver, "You must fill in a notification sender if notification is to be used.", true);
//        WebTestHelper.assertAlert(webDriver, "You must fill in a notification subject if notification is to be used.", true);
//        WebTestHelper.assertAlert(webDriver, "You must fill in a notification message if notification is to be used.", true);
//    }

//    @Test
//    public void g_addSecondAndThirdNotification() {
//        // Fill fields with 'second' and then click 'Add Another'
//        fillTopPrototype(secondText);
//        webDriver.findElement(By.xpath("//input[@name='buttonaddanothernotification']")).click();
//
//        // Fill fields with 'third' and then save
//        fillTopPrototype(thirdText);
//        EndEntityProfileHelper.save(webDriver, true);
//    }

//    @Test
//    public void g_disabledFields() {
//        EndEntityProfileHelper.edit(webDriver, eepName);
//
//        // Un-tick 'Use' and check that all fields become disabled
//        webDriver.findElement(By.id("checkboxusesendnotification")).click();
//        List<String> disabledElements = Arrays.asList(
//                "//input[@name='buttondeleteallnotification']",
//                "//input[@name='checkboxsendnotification']",
//                "//input[@name='checkboxrequiredsendnotification']",
//                "//input[@name='buttonaddnotification']",
//                "//input[@name='buttondeleltenotification2']",
//                "//input[@name='textfieldnotificationsender_newvalue2']",
//                "//input[@name='textfieldnotificationrcpt_newvalue2']",
//                "//select[@name='selectnotificationevents_newvalue2']",
//                "//input[@name='textfieldnotificationsubject_newvalue2']",
//                "//textarea[@name='textareanotificationmessage_newvalue2']",
//                "//input[@name='buttondeleltenotification1']",
//                "//input[@name='textfieldnotificationsender_newvalue1']",
//                "//input[@name='textfieldnotificationrcpt_newvalue1']",
//                "//select[@name='selectnotificationevents_newvalue1']",
//                "//input[@name='textfieldnotificationsubject_newvalue1']",
//                "//textarea[@name='textareanotificationmessage_newvalue1']",
//                "//input[@name='buttondeleltenotification0']",
//                "//input[@name='textfieldnotificationsender_newvalue0']",
//                "//input[@name='textfieldnotificationrcpt_newvalue0']",
//                "//select[@name='selectnotificationevents_newvalue0']",
//                "//input[@name='textfieldnotificationsubject_newvalue0']",
//                "//textarea[@name='textareanotificationmessage_newvalue0']"
//        );
//        for (String disabledElement : disabledElements) {
//            assertFalse("Element was not disabled: " + disabledElement, webDriver.findElement(By.xpath(disabledElement)).isEnabled());
//        }
//
//        // Tick 'Use' again and check that fields become enabled
//        webDriver.findElement(By.id("checkboxusesendnotification")).click();
//        for (String disabledElement : disabledElements) {
//            assertTrue("Element was not disabled: " + disabledElement, webDriver.findElement(By.xpath(disabledElement)).isEnabled());
//        }
//    }

//    @Test
//    public void h_deleteNotifications() {
//        // Click 'Delete' for prototype 'third' and check that it's deleted and that the other prototypes are intact
//        webDriver.findElement(By.xpath("//input[@name='buttondeleltenotification2']")).click();
//        try {
//            webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsender_newvalue2']"));
//            fail("Prototype 'third' still present");
//        } catch (NoSuchElementException e) {}
//        assertEquals("Top prototype had unexpected value", secondText, webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsender_newvalue1']")).getAttribute("value"));
//        assertEquals("Bottom prototype had unexpected value", firstText, webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsender_newvalue0']")).getAttribute("value"));
//
//        // Click 'Delete All', then cancel and restart editing
//        webDriver.findElement(By.xpath("//input[@name='buttondeleteallnotification']")).click();
//        EndEntityProfileHelper.cancel(webDriver);
//        EndEntityProfileHelper.edit(webDriver, eepName);
//
//        // Check that all prototypes are present
//        try {
//            webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsender_newvalue2']"));
//            webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsender_newvalue1']"));
//            webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsender_newvalue0']"));
//        } catch (NoSuchElementException e) {
//            fail("A prototype was not present");
//        }
//
//        // Click 'Delete All', save, edit and check that all prototypes are gone
//        webDriver.findElement(By.xpath("//input[@name='buttondeleteallnotification']")).click();
//        EndEntityProfileHelper.save(webDriver, true);
//        EndEntityProfileHelper.edit(webDriver, eepName);
//        try {
//            webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsender_newvalue2']"));
//            fail("Prototype 'third' was still present");
//        } catch (NoSuchElementException e) {}
//        try {
//            webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsender_newvalue1']"));
//            fail("Prototype 'second' was still present");
//        } catch (NoSuchElementException e) {}
//        try {
//            webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsender_newvalue0']"));
//            fail("Prototype 'first' was still present");
//        } catch (NoSuchElementException e) {}
//    }

//    private void openDocumentation(String xpath, String title) {
//        String mainWindow = webDriver.getWindowHandle();
//        String editWindow = null;
//
//        // Click [?] to open documentation (in another window)
//        webDriver.findElement(By.xpath(xpath)).click();
//        Set<String> handles = webDriver.getWindowHandles();
//        for (String handle : handles) {
//            if (!handle.equals(mainWindow)) {
//                editWindow = handle;
//                break;
//            }
//        }
//
//        // Make sure the correct page was opened
//        webDriver.switchTo().window(editWindow);
//        try {
//            webDriver.findElement(By.xpath("//h1/span[contains(text(), '" + title + "')]"));
//        } catch (NoSuchElementException e) {
//            fail("Documentation link opened the wrong page");
//        }
//
//        // Switch back to the main window
//        webDriver.close();
//        webDriver.switchTo().window(mainWindow);
//    }

//    private void fillTopPrototype(String text) {
//        WebElement senderField = webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsender']"));
//        WebElement recipientField = webDriver.findElement(By.xpath("//input[@name='textfieldnotificationrcpt']"));
//        WebElement subjectField = webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsubject']"));
//        WebElement messageField = webDriver.findElement(By.xpath("//textarea[@name='textareanotificationmessage']"));
//        senderField.sendKeys(text);
//        recipientField.clear();
//        recipientField.sendKeys(text);
//        subjectField.sendKeys(text);
//        messageField.sendKeys(text);
//    }
}
