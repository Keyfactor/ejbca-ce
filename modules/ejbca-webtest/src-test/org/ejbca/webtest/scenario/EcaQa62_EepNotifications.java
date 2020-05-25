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

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * This test checks the behavior of EEP Notifications in the edit view.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa62_EepNotifications extends WebTestBase {
    // Helpers
    private static EndEntityProfileHelper endEntityProfileHelper;

    // Test Data
    private static class TestData {
        private static final String EEP_NAME = "NotificationEEP-ECAQA-62";
        private static final String FIRST_TEXT = "first";
        private static final String SECOND_TEXT = "second";
        private static final String THIRD_TEXT = "third";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        removeEndEntityProfileByName(TestData.EEP_NAME);
        afterClass();
    }

    @Test
    public void a_addEep() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.EEP_NAME);

        // Verify that notifications are disabled by default
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.EEP_NAME);
        endEntityProfileHelper.assertUseSendNotificationIsSelected(false);
        endEntityProfileHelper.assertNotificationDoesNotExist();
    }

    // TODO ECA-7627 Documentation has to be built before this case works
//    @Ignore
//    @Test
//    public void b_checkDocumentation() {
//        openDocumentation("//strong[text()='Send Notification']/following-sibling::a", "E-mail Notifications");
//    }

    @Test
    public void c_enableNotifications() {
        // Check 'Use' and check that 'Default=', 'Required' and 'Add' are enabled (and not selected)
        endEntityProfileHelper.triggerSendNotification();
        endEntityProfileHelper.assertDefaultSendNotificationIsEnabled(true);
        endEntityProfileHelper.assertDefaultSendNotificationIsSelected(false);
        endEntityProfileHelper.assertRequiredSendNotificationIsEnabled(true);
        endEntityProfileHelper.assertRequiredSendNotificationIsSelected(false);
        endEntityProfileHelper.assertAddNotificationButtonIsEnabled(true);

        // Click 'Add' button and check that all the fields are added
        endEntityProfileHelper.addNotification();
        endEntityProfileHelper.assertNotificationSenderExists(0);
        endEntityProfileHelper.assertNotificationRecipientExists(0);
        endEntityProfileHelper.assertNotificationEventsExists();
        endEntityProfileHelper.assertNotificationSubjectExists(0);
        endEntityProfileHelper.assertNotificationMessageExists(0);
        endEntityProfileHelper.assertDeleteAllNotificationButtonIsEnabled(true);
    }

    // TODO ECA-7627 Documentation has to be built before this case works
//    @Ignore
//    @Test
//    public void d_checkDocumentation() {
//        openDocumentation("//td[contains(text(), 'Notification Subject')]/a", "Dynamic Substitution Variables");
//        openDocumentation("//td[contains(text(), 'Notification Message')]/a", "Dynamic Substitution Variables");
//    }

    @Test
    public void e_addAnotherNotification() {
        endEntityProfileHelper.addNotification();
        endEntityProfileHelper.assertNotificationSenderExists(0);
        endEntityProfileHelper.assertNotificationSenderExists(1);
        // Click 'Cancel' and make sure that the page looks like before
        endEntityProfileHelper.deleteAllNotifications();
        endEntityProfileHelper.assertNotificationSenderDoesNotExist(0);
    }

    @Test
    public void f_addFirstNotification() {
        endEntityProfileHelper.addNotification();

        // Fill fields with 'first' and then click 'Add Another'
        endEntityProfileHelper.fillNotification(0, TestData.FIRST_TEXT);
        endEntityProfileHelper.addNotification();
        // Make sure the new prototype is on top
        assertTrue("Top notification was not empty", endEntityProfileHelper.getNotificationSenderText(0).isEmpty());
        assertEquals("Bottom notification didn't contain expected value", TestData.FIRST_TEXT, endEntityProfileHelper.getNotificationSubjectValueText(1));
        assertEquals("Top notification didn't have 'Delete' button", "Delete", endEntityProfileHelper.getNotificationDeleteButtonValueText(0));
        assertEquals("Bottom notification didn't have 'Delete' button", "Delete", endEntityProfileHelper.getNotificationDeleteButtonValueText(1));

        // Click 'Save' and make sure the correct error messages are displayed
        endEntityProfileHelper.saveEndEntityProfile( false);
        endEntityProfileHelper.assertNotificationNotFilledErrorMessages();
    }

    @Test
    public void g_addSecondAndThirdNotification() {
        // Fill fields with 'second' and then click 'Add Another'
        endEntityProfileHelper.fillNotification(0, TestData.SECOND_TEXT);
        endEntityProfileHelper.addNotification();

        // Fill fields with 'third' and then save

        endEntityProfileHelper.fillNotification(0, TestData.THIRD_TEXT);
        endEntityProfileHelper.saveEndEntityProfile( true);
    }

    @Test
    public void g_disabledFields() {
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.EEP_NAME);

        // Un-tick 'Use' and check that all fields become disabled
        endEntityProfileHelper.triggerSendNotification();
        endEntityProfileHelper.verifyNotificationFieldsEnabled(false, 2);

        // Tick 'Use' again and check that fields become enabled
        endEntityProfileHelper.triggerSendNotification();
        endEntityProfileHelper.verifyNotificationFieldsEnabled(true, 2);
    }

    @Test
    public void h_deleteNotifications() {
        // Click 'Delete' for prototype 'third' and check that it's deleted and that the other prototypes are intact
        endEntityProfileHelper.deleteNotification(0);
        endEntityProfileHelper.assertNotificationSenderDoesNotExist(2);

        assertEquals("Top notification had unexpected value", TestData.SECOND_TEXT, endEntityProfileHelper.getNotificationSenderValueText(0));
        assertEquals("Bottom prototype had unexpected value", TestData.FIRST_TEXT, endEntityProfileHelper.getNotificationSenderValueText(1));

        // Click 'Delete All', then cancel and restart editing
        endEntityProfileHelper.deleteAllNotifications();
        endEntityProfileHelper.cancel();
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.EEP_NAME);

        // Check that all prototypes are present
        endEntityProfileHelper.assertNotificationSenderExists(2);
        endEntityProfileHelper.assertNotificationSenderExists(1);
        endEntityProfileHelper.assertNotificationSenderExists(0);

        // Click 'Delete All', save, edit and check that all prototypes are gone

        endEntityProfileHelper.deleteAllNotifications();
        endEntityProfileHelper.saveEndEntityProfile(true);
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.EEP_NAME);
        endEntityProfileHelper.assertNotificationSenderDoesNotExist(2);
        endEntityProfileHelper.assertNotificationSenderDoesNotExist(1);
        endEntityProfileHelper.assertNotificationSenderDoesNotExist(0);
    }

    // TODO ECA-7627
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

}
