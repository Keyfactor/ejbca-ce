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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
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

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("UserDataTest"));

    private static WebDriver webDriver;

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
        webDriver = getWebDriver();
        // Init helpers
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        removeEndEntityProfileByName(TestData.EEP_NAME);
        webDriver.quit();
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

    // TODO ECA-7349
    // TODO Documentation has to be built before this case works
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
        endEntityProfileHelper.assertNotificationSenderExists();
        endEntityProfileHelper.assertNotificationRecipientExists();
        endEntityProfileHelper.assertNotificationEventsExists();
        endEntityProfileHelper.assertNotificationSubjectExists();
        endEntityProfileHelper.assertNotificationMessageExists();
        endEntityProfileHelper.assertAddAnotherNotificationButtonExists();
        endEntityProfileHelper.assertCancelNotificationButtonIsEnabled(true);
    }

    // TODO ECA-7349
    // TODO Documentation has to be built before this case works
//    @Ignore
//    @Test
//    public void d_checkDocumentation() {
//        openDocumentation("//td[contains(text(), 'Notification Subject')]/a", "Dynamic Substitution Variables");
//        openDocumentation("//td[contains(text(), 'Notification Message')]/a", "Dynamic Substitution Variables");
//    }

    @Test
    public void e_addAnotherNotification() throws InterruptedException {
        //TODO ECA-7349 check after eep page convertion, alerts should be replaced with error messages.
//        endEntityProfileHelper.addAnotherNotification();
//        endEntityProfileHelper.assertNotificationNotFilledAllerts();

        // Click 'Cancel' and make sure that the page looks like before
        endEntityProfileHelper.cancelNotification();
        endEntityProfileHelper.assertNotificationSenderDoesNotExist();
    }

    @Test
    public void f_addFirstNotification() {
        endEntityProfileHelper.addNotification();

        // Fill fields with 'first' and then click 'Add Another'
        endEntityProfileHelper.fillNotification(TestData.FIRST_TEXT);
        endEntityProfileHelper.addAnotherNotification();
        // Make sure the new prototype is on top
        assertTrue("Top notification was not empty", endEntityProfileHelper.getNotificationSenderText().isEmpty());
        assertEquals("Bottom notification didn't contain expected value", TestData.FIRST_TEXT, endEntityProfileHelper.getNotificationSubjectValueText(0));
        assertEquals("Bottom notification didn't have 'Delete' button", "Delete", endEntityProfileHelper.getNotificationDeleteButtonValueText(0));

        // Click 'Save' and make sure the correct error messages are displayed
//        TODO ECA-7349 check after eep page convertion, alerts should be replaced with error messages.
//        endEntityProfileHelper.saveEndEntityProfile( false);
//        endEntityProfileHelper.assertNotificationNotFilledAllerts();
    }

    @Test
    public void g_addSecondAndThirdNotification() {
        // Fill fields with 'second' and then click 'Add Another'
        endEntityProfileHelper.fillNotification(TestData.SECOND_TEXT);
        endEntityProfileHelper.addAnotherNotification();

        // Fill fields with 'third' and then save

        endEntityProfileHelper.fillNotification(TestData.THIRD_TEXT);
        endEntityProfileHelper.saveEndEntityProfile( true);
    }

    //TODO ECA-7349 verify after jsf convertion. There may be a problem with indeces
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

    // TODO and ECA-7349
    @Test
    public void h_deleteNotifications() {
        // Click 'Delete' for prototype 'third' and check that it's deleted and that the other prototypes are intact
        endEntityProfileHelper.deleteNotification(2);
        endEntityProfileHelper.assertNotificationSenderDoesNotExist(2);

        assertEquals("Top notification had unexpected value", TestData.SECOND_TEXT, endEntityProfileHelper.getNotificationSenderValueText(1));
        assertEquals("Bottom prototype had unexpected value", TestData.FIRST_TEXT, endEntityProfileHelper.getNotificationSenderValueText(0));

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

    // TODO and ECA-7349
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
