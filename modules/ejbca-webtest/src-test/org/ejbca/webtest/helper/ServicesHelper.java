package org.ejbca.webtest.helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.List;

// TODO JavaDoc
/**
 * Services helper class for EJBCA Web Tests.
 *
 * @version $Id: ServicesHelper.java 30069 2018-10-08 17:45:09Z andrey_s_helmes $
 */
public class ServicesHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'Services' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/services/listservices.jsf";
        static final By PAGE_LINK = By.id("sysFuncsServices");
        // Services Form
        static final By INPUT_NAME = By.xpath("//input[contains(@name, 'newServiceName')]");
        static final By BUTTON_ADD = By.xpath("//input[contains(@name, 'addButton')]");
        static final By BUTTON_EDIT = By.xpath("//input[contains(@name, 'editButton')]");
        static final By BUTTON_DELETE = By.xpath("//input[contains(@name, 'deleteButton')]");
        static final By BUTTON_RENAME = By.xpath("//input[contains(@name, 'renameButton')]");
        static final By BUTTON_CLONE = By.xpath("//input[contains(@name, 'cloneButton')]");
        static final By SELECT_SERVICES_LIST = By.xpath("//select[@class='select-list']");
        static final By TEXT_ALERT = By.xpath("//table[@class='alert']");
        // Service Form
        static final By TEXT_SERVICE_TITLE = By.id("serviceTitle");
        static final By SELECT_WORKER = By.xpath("//select[contains(@name, 'selectWorker')]");
        static final By BUTTON_EDIT_SAVE = By.id("edit:saveButton");
    }

    public ServicesHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }

    public void addService(final String serviceName) {
        fillInput(Page.INPUT_NAME, serviceName);
        clickLink(Page.BUTTON_ADD);
    }

    public void openEditServicePage(final String serviceName) {
        // Select a service and click edit button
        selectOptionByValue(Page.SELECT_SERVICES_LIST, serviceName);
        clickLink(Page.BUTTON_EDIT);
        // Assert correct edit page
        assertServiceTitleExists(Page.TEXT_SERVICE_TITLE, "Service: ", serviceName);
    }

    public void editService(final String selectedWorker) {
        if(selectedWorker != null) {
            selectOptionByName(Page.SELECT_WORKER, selectedWorker);
        }
    }

    public void saveService() {
        clickLink(Page.BUTTON_EDIT_SAVE);
    }

    public void renameService(final String oldServiceName, final String newServiceName) {
        // Select a service, input name and click rename button
        selectOptionByValue(Page.SELECT_SERVICES_LIST, oldServiceName);
        fillInput(Page.INPUT_NAME, newServiceName);
        clickLink(Page.BUTTON_RENAME);
    }

    public void cloneService(final String serviceName, final String newServiceName) {
        // Select a service, input name and click clone button
        selectOptionByValue(Page.SELECT_SERVICES_LIST, serviceName);
        fillInput(Page.INPUT_NAME, newServiceName);
        clickLink(Page.BUTTON_CLONE);
    }

    public void deleteService(final String serviceName) {
        selectOptionByValue(Page.SELECT_SERVICES_LIST, serviceName);
        clickLink(Page.BUTTON_DELETE);
    }

    public void confirmServiceDeletion(final String message, final boolean isConfirmed) {
        assertAndConfirmAlertPopUp(message, isConfirmed);
    }

    public void assertServiceNameExists(final String serviceName) {
        final List<String> serviceNames = getSelectValues(Page.SELECT_SERVICES_LIST);
        assertNotNull("Cannot find list of services.", serviceNames);
        assertTrue("Cannot find service [" + serviceName + "] in the select", serviceNames.contains(serviceName));
    }

    public void assertServiceNameDoesNotExist(final String serviceName) {
        final List<String> serviceNames = getSelectValues(Page.SELECT_SERVICES_LIST);
        assertNotNull("Cannot find list of services.", serviceNames);
        assertFalse("Found service [" + serviceName + "] in the select", serviceNames.contains(serviceName));
    }

    public void assertWorkerHasSelectedName(final String name) {
        final List<String> selectedNames = getSelectSelectedNames(Page.SELECT_WORKER);
        assertNotNull("'Select Worker' was not found", selectedNames);
        assertTrue("CRL Updater was not selected", selectedNames.contains(name));
    }

    public void assertHasAlert(final String alertText) {
        final WebElement alertWebElement = findElement(Page.TEXT_ALERT);
        assertNotNull("Alert was not found", alertWebElement);
        assertEquals("No warning was given the service name already exists", alertText, alertWebElement.getText());
    }

    private void assertServiceTitleExists(final By textTitleId, final String prefixString, final String serviceName) {
        final WebElement serviceTitle = findElement(textTitleId);
        if(serviceName == null) {
            fail("Service title was not found.");
        }
        assertEquals(
                "Action on wrong Service.",
                prefixString + serviceName,
                serviceTitle.getText()
        );
    }

}
