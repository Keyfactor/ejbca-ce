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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.ejbca.webtest.util.WebTestUtil;
import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.NoAlertPresentException;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedCondition;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

/**
 * A base helper class for page operations of a web helper extensions.
 *
 * @version $Id$
 */
public class BaseHelper {

    private static final Logger log = Logger.getLogger(BaseHelper.class);

    protected WebDriver webDriver;

    public static class Page {
        static final By TEXT_MESSAGE = By.xpath("//*[@id='messages']//li[@class='infoMessage']");
        static final By TEXT_ERROR_MESSAGE = By.xpath("//*[@id='messages']//li[@class='errorMessage']");
    }

    /**
     * Built-in timeout for WebElement find.
     */
    static final int DEFAULT_WAIT_TIMEOUT_SECONDS = 10;

    /**
     * Selector's switch to select an option by name or value.
     */
    public enum SELECT_BY {
        // Text of the option
        TEXT,
        // Value of the option
        VALUE
    }

    /**
     * Public constructor.
     *
     * @param webDriver web driver.
     */
    public BaseHelper(final WebDriver webDriver) {
        this.webDriver = webDriver;
    }

    /**
     * Finds child web elements by locator using the built-in timeout for the visible parent element. Throws
     *
     * @param groupId locator.
     *
     * @return a list of child web elements.
     */
    protected List<WebElement> findElements(final By groupId) {
        // Wait
        waitForElementBecomeVisibleByLocator(groupId);
        return webDriver.findElements(groupId);
    }

    /**
     * Finds an element by locator using the built-in timeout for the visibility check.
     *
     * @param elementId locator.
     *
     * @return a web element.
     */
    protected WebElement findElement(final By elementId) {
        // Wait
        waitForElementBecomeVisibleByLocator(elementId);
        return findElementWithoutWait(elementId);
    }

    /**
     * Finds an element by locator.
     *
     * @param elementId locator.
     *
     * @return a web element or null.
     */
    WebElement findElementWithoutWait(final By elementId) {
        return findElementWithoutWait(elementId, true);
    }

    /**
     * Finds an element by locator.
     * <br/>
     * In case of missing element (as expected), use shouldLogError = false flag.
     *
     * @param elementId locator.
     * @param shouldLogError boolean flag, whether an error about non-existing element should be reported.
     *
     * @return a web element or null.
     */
    WebElement findElementWithoutWait(final By elementId, boolean shouldLogError) {
        try {
            return webDriver.findElement(elementId);
        }
        catch (NoSuchElementException ex) {
            if(shouldLogError) {
                log.debug("Cannot find WebElement [" + elementId.toString() + "]", ex);
            }
        }
        return null;
    }

    /**
     * Finds an element by locator within given element.
     *
     * @param rootElement    an input element.
     * @param childElementId child locator.
     *
     * @return a web element or null.
     */
    protected WebElement findElement(final WebElement rootElement, final By childElementId) {
        return findElement(rootElement, childElementId, true);
    }

    /**
     * Finds an element by locator within given element.
     * <br/>
     * In case of missing element (as expected), use shouldLogError = false flag.
     *
     * @param rootElement    an input element.
     * @param childElementId child locator.
     * @param shouldLogError boolean flag, whether an error about non-existing element should be reported.
     *
     * @return a web element or null.
     */
    protected WebElement findElement(final WebElement rootElement, final By childElementId, final boolean shouldLogError) {
        assertNotNull("Root element cannot be null.", rootElement);
        // Wait
        waitForElementBecomeVisible(rootElement);
        try {
            return rootElement.findElement(childElementId);
        }
        catch (NoSuchElementException ex) {
            if(shouldLogError) {
                log.debug("Cannot find WebElement [" + childElementId.toString() + "] inside WebElement [" + rootElement.getTagName() + "]", ex);
            }
        }
        return null;
    }

    /**
     * Finds child web elements by locator within given element.
     *
     * @param rootElement    an input element.
     * @param childElementId child locator.
     *
     * @return a list of child web elements.
     */
    protected List<WebElement> findElements(final WebElement rootElement, final By childElementId) {
        assertNotNull("Root element cannot be null.", rootElement);
        // Wait
        waitForElementBecomeVisible(rootElement);
        return rootElement.findElements(childElementId);
    }

    /**
     * Asserts a link (link, button, input, checkbox) by given locator exists and clicks it.
     *
     * @param linkId locator.
     */
    protected void clickLink(final By linkId) {
        clickLink(findElement(linkId));
    }

    /**
     * Asserts a link (link, button, input, checkbox) by given locator exists and clicks it.
     *
     * @param linkWebElement link web element.
     */
    protected void clickLink(final WebElement linkWebElement) {
        assertNotNull("Page link was not found", linkWebElement);
        linkWebElement.click();
    }

    /**
     * Toggles a check box to the desired state (checked or unchecked)
     * @param linkId check box locator
     * @param shouldBeEnabled true if the box should be checked. I.e. enabled.
     */
    void toggleCheckbox(final By linkId, final boolean shouldBeEnabled) {
        if ((!isSelectedElement(linkId) && shouldBeEnabled) ||
            (isSelectedElement(linkId) && !shouldBeEnabled)) {
            clickLink(linkId);
        }
    }

    /**
     * Clicks a link (link, button, input, checkbox) if it exists.
     *
     * @param linkId locator.
     */
    void clickLinkIfExists(final By linkId) {
        final WebElement linkWebElement = findElementWithoutWait(linkId);
        if (linkWebElement != null) {
            linkWebElement.click();
        }
    }

    /**
     * Asserts a given input exists and fills a text into it.
     *
     * @param inputId locator.
     * @param inputString input text.
     */
    protected void fillInput(final By inputId, final String inputString) {
        fillInput(findElement(inputId), inputString);
    }

    /**
     * Asserts a given input exists and fills a text into it.
     *
     * @param inputWebElement input web element.
     * @param inputString input text.
     */
    protected void fillInput(final WebElement inputWebElement, final String inputString) {
        assertNotNull("Page input was not found", inputWebElement);
        inputWebElement.clear();
        inputWebElement.sendKeys(inputString);
    }

    /**
     * Asserts a given textarea exists and replaces it's text.
     *
     * @param textareaId locator.
     * @param inputString input text.
     */
    void fillTextarea(final By textareaId, final String inputString) {
        final WebElement textareaWebElement = findElement(textareaId);
        assertNotNull("Page textarea was not found", textareaWebElement);
        textareaWebElement.clear();
        textareaWebElement.sendKeys(inputString);
    }

    /**
     * Asserts a given Swagger's textarea exists and replaces it's text.
     *
     * @param textareaId locator.
     * @param inputString input text.
     */
    void fillSwaggerTextarea(final By textareaId, final String inputString) {
        final WebElement textareaWebElement = findElement(textareaId);
        assertNotNull("Page textarea was not found", textareaWebElement);
        textareaWebElement.clear();
        textareaWebElement.sendKeys(Keys.ARROW_LEFT + inputString);
    }

    /**
     * Opens a given URL and asserts that actual URL matches the expected URI.
     *
     * @param webUrl      URL to open.
     * @param expectedUri URI to expect.
     */
    void openPageByUrlAndAssert(final String webUrl, final String expectedUri) {
        webDriver.get(webUrl);
        waitForJavaScriptLoad(webDriver);
        assertPageUri(expectedUri);
    }

    /**
     * Opens a given URL, clicks the link within opened page and asserts the resulting URL matches the expected URI.
     *
     * @param webUrl an URL to open.
     * @param pageLinkId link locator.
     * @param expectedUri URI to expect.
     */
    protected void openPageByLinkAndAssert(final String webUrl, final By pageLinkId, final String expectedUri) {
        webDriver.get(webUrl);
        clickLink(pageLinkId);
        assertPageUri(expectedUri);
    }

    /**
     * Asserts the actual URL matches the expected URI.
     *
     * @param expectedUri an URI to expect.
     */
    void assertPageUri(final String expectedUri) {
        assertEquals(
                "Wrong page URI expectation.",
                expectedUri,
                WebTestUtil.getUriPathFromUrl(webDriver.getCurrentUrl())
        );
    }

    /**
     * Selects a single option in the 'select' HTML element by name and asserts that the option is selected.
     *
     * @param selectId locator.
     * @param selectionOption option's names.
     */
    protected void selectOptionByName(final By selectId, final String selectionOption) {
        selectOptionByName(selectId, selectionOption, null);
    }

    /**
     * Selects a single option in the 'select' HTML element by name and asserts that the option is selected.
     *
     * @param selectId locator.
     * @param selectionOption option's names.
     * @param dependentElementId a dependent element, which appears/reloads on option selection. Used to check visibility after option is selected to avoid StaleElementReferenceException
     */
    protected void selectOptionByName(final By selectId, final String selectionOption, final By dependentElementId) {
        selectOptionsByName(selectId, Collections.singletonList(selectionOption), dependentElementId);
    }

    /**
     * Selects a single option in the 'select' HTML element by name without assertion of selection.
     *
     * @param selectWebElement select web element.
     * @param selectionOption option's names.
     */
    protected void selectOptionByName(final WebElement selectWebElement, final String selectionOption) {
        assertNotNull("Page select was not found", selectWebElement);
        selectOptions(new Select(selectWebElement), Collections.singletonList(selectionOption), SELECT_BY.TEXT);
    }

    /**
     * Selects a single option in the 'select' HTML element by value and asserts that the option is selected.
     *
     * @param selectId locator.
     * @param selectionOption option's value.
     */
    void selectOptionByValue(final By selectId, final String selectionOption) {
        selectOptionsByValue(selectId, Collections.singletonList(selectionOption));
    }

    /**
     * Selects options by name in the 'select' HTML element and asserts that all options are selected.
     *
     * @param selectId locator.
     * @param selectionOptions  a list of option names to select.
     */
    void selectOptionsByName(final By selectId, final List<String> selectionOptions) {
        selectOptionsByName(selectId, selectionOptions, null);
    }

    /**
     * Selects options by name in the 'select' HTML element and asserts that all options are selected.
     *
     * @param selectId locator.
     * @param selectionOptions  a list of option names to select.
     * @param dependentElementId  a dependent element, which appears/ reloads on option selection. Used to check visibility after option is selected to avoid StaleElementReferenceException
     */
    void selectOptionsByName(final By selectId, final List<String> selectionOptions, final By dependentElementId) {
        waitForElementBecomeVisibleByLocator(selectId);
        final WebElement selectWebElement = findElement(selectId);
        assertNotNull("Page select was not found", selectWebElement);
        selectOptions(new Select(selectWebElement), selectionOptions, SELECT_BY.TEXT);
        // For assertion, reload the object as a selection may trigger the refresh/reload event and modify the DOM
        // which causes the org.openqa.selenium.StaleElementReferenceException
        if (dependentElementId != null) {
            findElement(dependentElementId);
        }
        final WebElement selectedWebElement = findElement(selectId);
        assertSelectionOfAllOptions(new Select(selectedWebElement), selectionOptions, SELECT_BY.TEXT);
    }

    /**
     * Selects options by name in the 'select' HTML element one by one to support possible Ajax update.
     * Asserts that all options are selected.
     *
     * @param selectId locator.
     * @param selectionOptions  a list of option names to select.
     * @param dependentElementId  a dependent element, which appears/ reloads on option selection. Used to check visibility after option is selected to avoid StaleElementReferenceException
     */
    void selectOptionsByNameWithAjax(final By selectId, final List<String> selectionOptions, final By dependentElementId) {
        for(String selectionOption : selectionOptions) {
            waitForElementBecomeVisibleByLocator(selectId);
            final WebElement selectWebElement = findElement(selectId);
            assertNotNull("Page select was not found", selectWebElement);
            selectOptions(new Select(selectWebElement), Collections.singletonList(selectionOption), SELECT_BY.TEXT);
            // For assertion, reload the object as a selection may trigger the refresh/reload event and modify the DOM
            // which causes the org.openqa.selenium.StaleElementReferenceException
            if (dependentElementId != null) {
                findElement(dependentElementId);
            }
        }
        final WebElement selectedWebElement = findElement(selectId);
        assertSelectionOfAllOptions(new Select(selectedWebElement), selectionOptions, SELECT_BY.TEXT);
    }

    /**
     * Deselects all options in multi-select dropdown.
     *
     * @param selectId locator.
     * @see #deselectOptionsWithAjax(By)
     */
    void deselectOptions(final By selectId) {
        deselectOptions(findElement(selectId));
    }

    /**
     * Deselects all options in multi-select dropdown.
     *
     * @param selectWebElement select web element.
     */
    void deselectOptions(final WebElement selectWebElement) {
        assertNotNull("Page select was not found", selectWebElement);
        deselectOptions(new Select(selectWebElement));
    }

    /**
     * Deselects all options in multi-select dropdown one by one to support possible Ajax update.
     *
     * @param selectId locator.
     */
    void deselectOptionsWithAjax(final By selectId) {
        WebElement selectWebElement = findElement(selectId);
        assertNotNull("Page select was not found", selectWebElement);
        Select select = new Select(selectWebElement);
        final int selectOptionsSize = (select.getOptions() != null ? select.getOptions().size() : 0);
        for(int index = 0; index < selectOptionsSize; index++) {
            // Re-init
            selectWebElement = findElement(selectId);
            select = new Select(selectWebElement);
            select.deselectByIndex(index);
        }
    }

    /**
     * Selects options by value in the 'select' HTML element and asserts that all options are selected.
     *
     * @param selectId locator.
     * @param selectionOptions  A list of option values to select.
     */
    private void selectOptionsByValue(final By selectId, final List<String> selectionOptions) {
        final WebElement selectWebElement = findElement(selectId);
        assertNotNull("Page select was not found", selectWebElement);
        selectOptions(new Select(selectWebElement), selectionOptions, SELECT_BY.VALUE);
        // For assertion, reload the object as a selection may trigger the refresh/reload event and modify the DOM
        // which causes the org.openqa.selenium.StaleElementReferenceException
        final WebElement selectedWebElement = findElement(selectId);
        assertSelectionOfAllOptions(new Select(selectedWebElement), selectionOptions, SELECT_BY.VALUE);
    }

    /**
     * Returns true if an element by a given locator is 'input', false otherwise.
     *
     * @param elementId locator.
     *
     * @return true if an element by a given locator is 'input', false otherwise.
     */
    boolean isInputElement(final By elementId) {
        return isInputElement(findElement(elementId));
    }

    /**
     * Returns true if an element is 'input', false otherwise.
     *
     * @param webElement a web element.
     *
     * @return true if an element is 'input', false otherwise.
     */
    private boolean isInputElement(final WebElement webElement) {
        return webElement != null && webElement.getTagName().equalsIgnoreCase("input");
    }

    /**
     * Returns true if an element by a given locator is 'select', false otherwise.
     *
     * @param elementId locator.
     *
     * @return true if an element by a given locator is 'select', false otherwise.
     */
    boolean isSelectElement(final By elementId) {
        return isSelectElement(findElement(elementId));
    }

    /**
     * Returns true if an element is 'select', false otherwise.
     *
     * @param webElement a web element.
     *
     * @return true if an element is 'select', false otherwise.
     */
    private boolean isSelectElement(final WebElement webElement) {
        return webElement != null && webElement.getTagName().equalsIgnoreCase("select");
    }

    /**
     * Returns true if an element is 'td', false otherwise.
     *
     * @param webElement a web element.
     *
     * @return true if an element is 'td', false otherwise.
     */
    boolean isTdElement(final WebElement webElement) {
        return webElement != null && webElement.getTagName().equalsIgnoreCase("td");
    }

    /**
     * Asserts an element by locator exists.
     *
     * @param elementId      locator.
     * @param failureMessage failure message.
     */
    protected void assertElementExists(final By elementId, final String failureMessage) {
        if (findElement(elementId) == null) {
            fail(failureMessage);
        }
    }

    /**
     * Asserts an element by locator does not exist.
     *
     * @param elementId      locator.
     * @param failureMessage failure message.
     */
    void assertElementDoesNotExist(final By elementId, final String failureMessage) {
        if (findElementWithoutWait(elementId, false) != null) {
            fail(failureMessage);
        }
    }

    /**
     * Asserts a given element exists and returns its value (attribute 'value').
     *
     * @param elementId locator.
     *
     * @return element's value or null.
     */
    String getElementValue(final By elementId) {
        return getElementValue(findElement(elementId));
    }

    /**
     * Asserts a given element is not null and returns its value (attribute 'value').
     *
     * @param webElement non-null web element.
     *
     * @return element's value or null.
     */
    String getElementValue(final WebElement webElement) {
        if(webElement != null) {
            return webElement.getAttribute("value");
        }
        return null;
    }

    /**
     * Asserts a given element exists and returns its href (attribute 'href').
     *
     * @param elementId locator.
     *
     * @return element's value or null.
     */
    String getElementHref(final By elementId) {
        return getElementHref(findElement(elementId));
    }

    /**
     * Asserts a given element is not null and returns its href (attribute 'href').
     *
     * @param webElement non-null web element.
     *
     * @return element's value or null.
     */
    private String getElementHref(final WebElement webElement) {
        if(webElement != null) {
            return webElement.getAttribute("href");
        }
        return null;
    }

    /**
     * Asserts a given element exists and returns its text.
     *
     * @param elementId locator.
     *
     * @return element's text or null.
     */
    String getElementText(final By elementId) {
        return getElementText(findElement(elementId));
    }

    /**
     * Asserts a given element is not null and returns its text.
     *
     * @param webElement webElement non-null web element.
     *
     * @return element's text or null.
     */
    protected String getElementText(final WebElement webElement) {
        if(webElement != null) {
            return webElement.getText();
        }
        return null;
    }

    /**
     * Asserts a given element exists and returns whether it is selected.
     *
     * @param elementId locator.
     *
     * @return true if element is selected, false otherwise.
     */
    boolean isSelectedElement(final By elementId) {
        return isSelectedElement(findElement(elementId));
    }

    /**
     * Asserts a given element is not null and returns whether it is selected.
     *
     * @param webElement non-null web element.
     *
     * @return true if element is selected, false otherwise.
     */
    private boolean isSelectedElement(final WebElement webElement) {
        return webElement != null && webElement.isSelected();
    }

    /**
     * Asserts a given element is not null and returns whether it is enabled.
     *
     * @param elementId locator.
     *
     * @return true if element is enabled, false otherwise.
     */
    boolean isEnabledElement(final By elementId) {
        return isEnabledElement(findElement(elementId));
    }

    /**
     * Asserts a given element is not null and returns whether it is enabled.
     *
     * @param webElement non-null web element.
     *
     * @return true if element is enabled, false otherwise.
     */
    boolean isEnabledElement(final WebElement webElement) {
        return webElement != null && webElement.isEnabled();
    }

    /**
     * Returns the list of possible values for the non-null select.
     *
     * @param selectId locator.
     *
     * @return the list of values or null.
     */
    List<String> getSelectValues(final By selectId) {
        return getSelectValues(findElement(selectId));
    }

    /**
     * Returns the list of possible values for the non-null select.
     *
     * @param webElement non-null web element.
     *
     * @return the list of values or null.
     */
    private List<String> getSelectValues(final WebElement webElement) {
        if(webElement != null) {
            final List<String> selectNames = new ArrayList<>();
            final Select select = new Select(webElement);
            for(final WebElement selectOptionWebElement : select.getOptions()) {
                selectNames.add(getElementValue(selectOptionWebElement));
            }
            return selectNames;
        }
        return null;
    }

    /**
     * Returns the list of possible names for the non-null select.
     *
     * @param selectId locator.
     * @return the list of names or null.
     */
    List<String> getSelectNames(final By selectId) {
        return getSelectNames(findElement(selectId));
    }

    /**
     * Returns the list of possible names for the non-null select.
     *
     * @param webElement non-null web element.
     * @return the list of names or null.
     */
    List<String> getSelectNames(final WebElement webElement) {
        if (webElement != null) {
            final List<String> selectNames = new ArrayList<>();
            final Select select = new Select(webElement);
            for (final WebElement selectOptionWebElement : select.getOptions()) {
                selectNames.add(selectOptionWebElement.getText());
            }
            return selectNames;
        }
        return null;
    }

    /**
     * Returns the list of selected names for the non-null select.
     *
     * @param selectId locator.
     *
     * @return the list of selected names of a select or null.
     */
    List<String> getSelectSelectedNames(final By selectId) {
        return getSelectSelectedNames(findElement(selectId));
    }

    /**
     * Returns the list of selected names for the non-null select.
     *
     * @param webElement non-null web element.
     *
     * @return the list of selected names of a select or null.
     */
    List<String> getSelectSelectedNames(final WebElement webElement) {
        if(webElement != null) {
            final List<String> selectedNames = new ArrayList<>();
            final Select select = new Select(webElement);
            for (final WebElement selected : select.getAllSelectedOptions()) {
                selectedNames.add(selected.getText());
            }
            return selectedNames;
        }
        return null;
    }
    /**
     * Returns the first selected text of select element.
     *
     * @param selectId locator.
     *
     * @return the first selected element of a select or null.
     */
    String getFirstSelectedOption(final By selectId) {
        return getFirstSelectedOption(findElement(selectId));
    }

    /**
     * Returns the first selected text of select element.
     *
     * @param webElement non-null web element.
     * @return the first selected element of a select or null.
     */
    String getFirstSelectedOption(final WebElement webElement) {
        if (webElement != null) {
            final Select select = new Select(webElement);
            return getElementText(select.getFirstSelectedOption());
        }
        return null;
    }

    /**
     * Switches to 'next' browser window e.g. a pop-up or a new tab
     * Use return value to return to main window.
     * @return The main window (switched from). 
     */
    String switchToNextWindow() {
        final String mainWindow = webDriver.getWindowHandle();
        for (String window : webDriver.getWindowHandles()) {
            if (!window.equals(mainWindow)) {
                switchToWindow(window);
            }
        }
        return mainWindow;
    }
    
    /**
     * Switch to the specified window
     * @param windowId of the window to switch to.
     */
    void switchToWindow(final String windowId) {
        webDriver.switchTo().window(windowId);
    }
    
    /**
     * Asserts the appearance of the alert popup, its message and accepts/discards it.
     *
     * @param expectedAlertMessageText the expected alert's message.
     * @param isConfirmed a flag to accept or discard the alert.
     */
    void assertAndConfirmAlertPopUp(final String expectedAlertMessageText, boolean isConfirmed) {
        try {
            final Alert alert = waitForAlertIsPresent();
            // Assert that the correct alert message is displayed (if not null)
            if (expectedAlertMessageText != null) {
                assertEquals("Unexpected alert message.", expectedAlertMessageText, alert.getText());
            }
            if (isConfirmed) {
                alert.accept();
            } else {
                alert.dismiss();
            }
        } catch (NoAlertPresentException e) {
            fail("Expected an alert but there was none");
        }
    }

    /**
     * Some pages executes JavaScript on load which may cause StaleElementException if executed after
     * webelement is selected. Invoke this method to wait for document to be ready before interacting with
     * webelements
     * @param driver Selenium Web Driver.
     */
    private void waitForJavaScriptLoad(WebDriver driver) {
        ExpectedCondition<Boolean> pageLoadCondition = driver1 -> ((org.openqa.selenium.JavascriptExecutor) driver1).executeScript("return document.readyState").equals("complete");
        WebDriverWait wait = new WebDriverWait(driver, 5);
        wait.until(pageLoadCondition);
    }

    private void deselectOptions(final Select selectObject) {
        selectObject.deselectAll();
    }

    // Selects options of a select
    private void selectOptions(final Select selectObject, final List<String> options, final SELECT_BY selectBy) {
        for (final String option : options) {
            switch (selectBy) {
                case TEXT:
                    selectObject.selectByVisibleText(option);
                    break;
                case VALUE:
                    selectObject.selectByValue(option);
                    break;
                default:
                    // Do nothing
            }
        }
    }

    // Asserts the given list of options was selected
    private void assertSelectionOfAllOptions(final Select selectObject, final List<String> options, final SELECT_BY selectBy) {
        for (final String option : options) {
            boolean isSelected = false;
            for (final WebElement selected : selectObject.getAllSelectedOptions()) {
                switch (selectBy) {
                    case TEXT:
                        // Assert that there is a selected option with the name
                        if (selected.getText().equals(option)) {
                            isSelected = true;
                        }
                        break;
                    case VALUE:
                        // Assert that there is a selected option with the value
                        if (getElementValue(selected).equals(option)) {
                            isSelected = true;
                        }
                        break;
                    default:
                        // Do nothing
                }
                if(isSelected) {
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

    private Alert waitForAlertIsPresent() {
        final WebDriverWait wait = new WebDriverWait(webDriver, DEFAULT_WAIT_TIMEOUT_SECONDS);
        return wait.until(ExpectedConditions.alertIsPresent());
    }

    /**
     * Asserts that the message (element Page.TEXT_MESSAGE) appears on the screen and matches the given regular expression.
     *
     * @param regex a regular expression which must match the actual message shown on the screen.
     * @param noSuchElementAssertionMessage the assertion error message to display if the message was not shown on the screen.
     * @param notMatchingRegexAssertionMessage the assertion error message to display if the message was shown on the screen but did not match the given regular expression.
     */
    void assertInfoMessageAppears(final String regex, final String noSuchElementAssertionMessage,
            final String notMatchingRegexAssertionMessage) {
        final WebElement message = findElement(Page.TEXT_MESSAGE);
        if (message == null) {
            fail(noSuchElementAssertionMessage);
        }
        assertTrue(notMatchingRegexAssertionMessage, Pattern.matches(regex, message.getText()));
    }

    /**
     * Asserts error Message appears with correct message text
     *
     * @param expectedErrorMessage expected error messages.
     * @param noElementMessage message if element doesn't exist.
     * @param assertMessage message text.
     */
    void assertErrorMessageAppears(final String expectedErrorMessage, final String noElementMessage, final String assertMessage) {
        assertAllErrorMessagesAppear(new String[]{expectedErrorMessage}, noElementMessage, assertMessage);
    }

    /**
     * Asserts all error Messages appears with correct message text
     *
     * @param expectedErrorMessages expected error messages.
     * @param noElementMessage message if element doesn't exist.
     * @param assertMessage message text.
     */
    void assertAllErrorMessagesAppear(final String[] expectedErrorMessages, final String noElementMessage, final String assertMessage) {
        List<WebElement> errorMessages = findElements(Page.TEXT_ERROR_MESSAGE);
        if (errorMessages == null) {
            fail(noElementMessage);
        }
        assertEquals("Expected number of error messages is not equal to actual one", expectedErrorMessages.length, errorMessages.size());
        for (int i = 0; i < errorMessages.size(); i++) {
            assertEquals(
                    assertMessage,
                    expectedErrorMessages[i],
                    errorMessages.get(i).getText()
            );
        }
    }
}
