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

import org.apache.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import org.ejbca.webtest.util.WebTestUtil;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

// TODO JavaDoc
/**
 * A base helper class for page operations of a web test.
 *
 * @version $Id: BaseHelper.java 30035 2018-10-05 08:35:05Z andrey_s_helmes $
 *
 */
public class BaseHelper {

    private static final Logger log = Logger.getLogger(BaseHelper.class);

    protected static WebDriver webDriver;

    public static final int DEFAULT_WAIT_TIMEOUT_SECONDS = 3;

    protected List<WebElement> findElements(final By groupId) {
        // Wait
        waitForElementBecomeVisibleByLocator(groupId);
        return webDriver.findElements(groupId);
    }

    protected WebElement findElement(final By elementId) {
        // Wait
        waitForElementBecomeVisibleByLocator(elementId);
        return findElementWithoutWait(elementId);
    }

    protected WebElement findElementWithoutWait(final By elementId) {
        try {
            return webDriver.findElement(elementId);
        }
        catch (NoSuchElementException ex) {
            log.debug("Cannot find WebElement [" + elementId.toString() + "]", ex);
        }
        return null;
    }

    protected WebElement findElement(final WebElement rootElement, final By childElementId) {
        assertNotNull("Root element cannot be null.", rootElement);
        // Wait
        waitForElementBecomeVisible(rootElement);
        try {
            return rootElement.findElement(childElementId);
        }
        catch (NoSuchElementException ex) {
            log.debug("Cannot find WebElement [" + childElementId.toString() + "] inside WebElement [" + rootElement.getTagName() + "]", ex);
        }
        return null;
    }

    public BaseHelper(final WebDriver webDriver) {
        this.webDriver = webDriver;
    }

    protected void clickLink(final By linkId) {
        final WebElement linkWebElement = findElement(linkId);
        assertNotNull("Page link was not found", linkWebElement);
        linkWebElement.click();
    }

    protected void clickLinkIfExists(final By linkId) {
        final WebElement linkWebElement = findElement(linkId);
        if(linkWebElement != null) {
            linkWebElement.click();
        }
    }

    protected void fillInput(final By inputId, final String inputString) {
        final WebElement inputWebElement = findElement(inputId);
        assertNotNull("Page input was not found", inputWebElement);
        inputWebElement.clear();
        inputWebElement.sendKeys(inputString);
    }

    protected void fillTextarea(final By textareaId, final String inputString, boolean doClear) {
        final WebElement textareaWebElement = findElement(textareaId);
        assertNotNull("Page textarea was not found", textareaWebElement);
        if(doClear) {
            textareaWebElement.clear();
        }
        textareaWebElement.sendKeys(inputString);
    }

    protected void openPageByUrlAndAssert(final String webUrl, final String expectedUri) {
        webDriver.get(webUrl);
        assertEquals(
                "Cannot open page [" + expectedUri + "]",
                expectedUri,
                WebTestUtil.getUriPathFromUrl(webDriver.getCurrentUrl())
        );
    }

    protected void openPageByLinkAndAssert(final String webUrl, final By pageLinkId, final String expectedUri) {
        webDriver.get(webUrl);
        clickLink(pageLinkId);
        assertEquals(
                "Cannot open page [" + expectedUri + "]",
                expectedUri,
                WebTestUtil.getUriPathFromUrl(webDriver.getCurrentUrl())
        );
    }

    /**
     * Selects a single option in the 'select' HTML element and asserts that the option is selected.
     *
     * @param selectByReference By reference of a select.
     * @param selectionOption Option names to select.
     */
    protected void selectOptionByName(final By selectByReference, final String selectionOption) {
        selectOptionsByName(selectByReference, Collections.singletonList(selectionOption), false);
    }

    /**
     * Selects options by name in the 'select' HTML element and asserts that all options are selected.
     *
     * @param selectByReference By reference of a select.
     * @param selectionOptions  A list of option names to select.
     */
    protected void selectOptionsByName(final By selectByReference, final List<String> selectionOptions) {
        selectOptionsByName(selectByReference, selectionOptions, true);
    }

    /**
     * Selects options by name in the 'select' HTML element and asserts that all options are selected.
     *
     * @param selectByReference By reference of a select.
     * @param selectionOptions  A list of option names to select.
     */
    protected void selectOptionsByName(final By selectByReference, final List<String> selectionOptions, final boolean useDeselectAll) {
        final WebElement selectWebElement = findElement(selectByReference);
        assertNotNull("Page select was not found", selectWebElement);
        selectOptions(new Select(selectWebElement), selectionOptions, useDeselectAll);
        // For assertion, reload the object as a selection may trigger the refresh/reload event and modify the DOM
        // which causes the org.openqa.selenium.StaleElementReferenceException
        final WebElement selectedWebElement = findElement(selectByReference);
        assertSelectionOfAllOptions(new Select(selectedWebElement), selectionOptions);
    }

    protected boolean isInputElement(final By elementId) {
        return isInputElement(findElement(elementId));
    }

    protected boolean isInputElement(final WebElement webElement) {
        if(webElement != null && webElement.getTagName().equalsIgnoreCase("input")) {
            return true;
        }
        return false;
    }

    protected boolean isSelectElement(final By elementId) {
        return isSelectElement(findElement(elementId));
    }

    protected boolean isSelectElement(final WebElement webElement) {
        if(webElement != null && webElement.getTagName().equalsIgnoreCase("select")) {
            return true;
        }
        return false;
    }

    protected boolean isTdElement(final By elementId) {
        return isTdElement(findElement(elementId));
    }

    protected boolean isTdElement(final WebElement webElement) {
        if(webElement != null && webElement.getTagName().equalsIgnoreCase("td")) {
            return true;
        }
        return false;
    }

    protected void assertElementExists(final By elementId, final String failureMessage) {
        if(findElement(elementId) == null) {
            fail(failureMessage);
        }
    }

    protected void assertElementDoesNotExist(final By elementId, final String failureMessage) {
        if(findElementWithoutWait(elementId) != null) {
            fail(failureMessage);
        }
    }

    protected String getElementValue(final By elementId) {
        return getElementValue(findElement(elementId));
    }

    protected String getElementValue(final WebElement webElement) {
        if(webElement != null) {
            return webElement.getAttribute("value");
        }
        return null;
    }

    protected boolean isSelectedElement(final By elementId) {
        return isSelectedElement(findElement(elementId));
    }

    protected boolean isSelectedElement(final WebElement webElement) {
        if(webElement != null) {
            return webElement.isSelected();
        }
        return false;
    }

    protected boolean isEnabledElement(final By elementId) {
        return isEnabledElement(findElement(elementId));
    }

    protected boolean isEnabledElement(final WebElement webElement) {
        if(webElement != null) {
            return webElement.isEnabled();
        }
        return false;
    }

    protected List<String> getSelectSelectedValues(final By selectId) {
        return getSelectSelectedValues(findElement(selectId));
    }

    protected List<String> getSelectSelectedValues(final WebElement webElement) {
        if(webElement != null) {
            final List<String> selectedNames = new ArrayList<String>();
            final Select select = new Select(webElement);
            for (final WebElement selected : select.getAllSelectedOptions()) {
                selectedNames.add(selected.getText());
            }
            return selectedNames;
        }
        return null;
    }

    private void selectOptions(final Select selectObject, final List<String> options, boolean useDeselectAll) {
        if(useDeselectAll) {
            selectObject.deselectAll();
        }
        for (final String option : options) {
            selectObject.selectByVisibleText(option);
        }
    }

    private void assertSelectionOfAllOptions(final Select selectObject, final List<String> options) {
        for (final String option : options) {
            boolean isSelected = false;
            for (final WebElement selected : selectObject.getAllSelectedOptions()) {
                // Assert that there is a selected option with the name
                if (selected.getText().equals(option)) {
                    isSelected = true;
                    break;
                }
            }
            assertTrue("The option " + option + " was not found", isSelected);
        }
    }

    // Add a delay-timeout for DOM object search to make sure the document is fully loaded and we don't get a stale exception
    private void waitForElementBecomeVisibleByLocator(final By objectBy) {
        // A bug in EJBCA requires a wait here, otherwise it results in an XML Parsing Error
        final WebDriverWait wait = new WebDriverWait(webDriver, DEFAULT_WAIT_TIMEOUT_SECONDS);
        wait.until(ExpectedConditions.visibilityOfElementLocated(objectBy));
    }

    // Add a delay-timeout for DOM object search to make sure the document is fully loaded and we don't get a stale exception
    private void waitForElementBecomeVisible(final WebElement webElement) {
        // A bug in EJBCA requires a wait here, otherwise it results in an XML Parsing Error
        final WebDriverWait wait = new WebDriverWait(webDriver, DEFAULT_WAIT_TIMEOUT_SECONDS);
        wait.until(ExpectedConditions.visibilityOf(webElement));
    }

}
