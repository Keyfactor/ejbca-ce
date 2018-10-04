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
import org.openqa.selenium.support.ui.Select;

import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

// TODO JavaDoc
/**
 * A base helper class for page operations of a web test.
 *
 * @version $Id: BaseTestHelper.java 28852 2018-05-04 14:35:13Z andrey_s_helmes $
 *
 */
public class BaseTestHelper {

    private static final Logger log = Logger.getLogger(BaseTestHelper.class);
    protected static WebDriver webDriver;

    protected List<WebElement> findElements(final By groupId) {
        return webDriver.findElements(groupId);
    }

    protected WebElement findElement(final By elementId) {
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
        try {
            return rootElement.findElement(childElementId);
        }
        catch (NoSuchElementException ex) {
            log.debug("Cannot find WebElement [" + childElementId.toString() + "] inside WebElement [" + rootElement.getTagName() + "]", ex);
        }
        return null;
    }

    public BaseTestHelper(final WebDriver webDriver) {
        this.webDriver = webDriver;
    }

    protected void clickLink(final By linkId) {
        final WebElement linkWebElement = findElement(linkId);
        assertNotNull("Page link was not found", linkWebElement);
        linkWebElement.click();
    }

    protected void fillInput(final By inputId, final String inputString) {
        final WebElement inputWebElement = findElement(inputId);
        assertNotNull("Page input was not found", inputWebElement);
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
}
