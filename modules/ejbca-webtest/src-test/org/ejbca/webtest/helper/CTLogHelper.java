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
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.io.File;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

/**
 * 
 * @version $Id$
 *
 */
public class CTLogHelper extends BaseHelper {
    public CTLogHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    public static class Page {
        static final By LOG_URL_INPUT_FIELD = By.id("ctlogsform:ctLogUrlInput");
        static final By PUBLIC_KEY_INPUT_FIELD = By.id("ctlogsform:currentCTLogKeyFile");
        static final By TIMEOUT_INPUT_FIELD = By.id("ctlogsform:ctLogTimeoutInput");
        static final By LABEL_INPUT_FIELD = By.id("ctlogsform:ctLogLabelInput");
        static final By BUTTON_ADD = By.id("ctlogsform:addCtLog");
        static final By TABLE_ROW_DATA = By.xpath("//table[@class='grid ctlogTable']/tbody/tr/td[1]/span");
        static final By EDIT_LOG_URL_INPUT_FIELD = By.id("editCtLogForm:logUrl");
        static final By EDIT_TIMEOUT_INPUT_FIELD = By.id("editCtLogForm:editedCTLogTimeout");
        static final By EDIT_LABEL_INPUT_FIELD = By.id("editCtLogForm:editedCtLogLabel");
        static final By BUTTON_EDIT_CTLOG = By.id("editCtLogForm:saveCtLogEdit");

        static By getLabelTextFromTable(final String text) {
            return By.xpath("//tr/td/h3[contains(text(), '" + text + "')]");
        }

        static By getLogURLTextFromTableRow(final String rowText) {
            return By.xpath("//tr/td/table[@class='grid ctlogTable']/tbody/tr/td/span[@title='Log URL'][contains(text(), '" + rowText + "')]");
        }

        static By getNavigateDownButton(final String label, final String text) {
            return By.xpath("//table/tbody/tr/td/h3[contains(text(), '" + label + "')]" +
                    "/following-sibling::table[@class='grid ctlogTable']/" +
                    "tbody/tr/td[span[contains(text(), '" + text + "')]]/" +
                    "following-sibling::td/input[contains(@id, 'moveDownCtLogButton')]");
        }

        static By getNavigateUpButton(final String label, final String text) {
            return By.xpath("//table/tbody/tr/td/h3[contains(text(), '" + label + "')]" +
                    "/following-sibling::table[@class='grid ctlogTable']/" +
                    "tbody/tr/td[span[contains(text(), '" + text + "')]]/" +
                    "following-sibling::td/input[contains(@id, 'moveUpCtLogButton')]");
        }
        
        static By getEditCtLogButton(final String label, final String text) {
            return By.xpath("//table/tbody/tr/td/h3[contains(text(), '" + label + "')]" +
                    "/following-sibling::table[@class='grid ctlogTable']/" +
                    "tbody/tr/td[span[contains(text(), '" + text + "')]]/" +
                    "following-sibling::td/input[contains(@id, 'editCtLogButton')]");
        }
    }

    public void fillLogUrlField(final String inputText) {
        fillInput(Page.LOG_URL_INPUT_FIELD, inputText);
    }

    public void fillPublicKeyField(final File inputFile) {
        fillInput(Page.PUBLIC_KEY_INPUT_FIELD, inputFile.toString());
    }

    public void fillTimeoutField(final int inputNumber) {
        fillInput(Page.TIMEOUT_INPUT_FIELD, String.valueOf(inputNumber));
    }

    public void fillLabelField(final String inputText) {
        fillInput(Page.LABEL_INPUT_FIELD, inputText);
    }
    
    public void fillEditLogUrlField(final String inputText) {
        fillInput(Page.EDIT_LOG_URL_INPUT_FIELD, inputText);
    }
    
    public void fillEditTimeoutField(final String inputNumber) {
        fillInput(Page.EDIT_TIMEOUT_INPUT_FIELD, inputNumber);
    }
    
    public void fillEditLabelField(final String inputText) {
        fillInput(Page.EDIT_LABEL_INPUT_FIELD, inputText);
    }

    public void addCertificateTransparencyLog() {
        clickLink(Page.BUTTON_ADD);
    }

    public void assertIsTableAndRowExists(final String matchLabelWith, final String matchRowWith) {
        assertElementExists(Page.getLabelTextFromTable(matchLabelWith), "Element label:" + matchLabelWith + " does not exist from table.");
        assertElementExists(Page.getLogURLTextFromTableRow(matchRowWith), "Element " + matchRowWith + " does not exist from table row.");
    }

    public void assertIsTableRowsCorrectOrder(int rowNum, String rowData) {
        final List<WebElement> tableRows = findElements(Page.TABLE_ROW_DATA);
        assertEquals(tableRows.get(rowNum).getText(), rowData);
    }

    public void pressArrowUpButton(final String label, final String text) {
        clickLink(Page.getNavigateUpButton(label, text));
    }

    public void pressArrowDownButton(final String label, final String text) {
        clickLink(Page.getNavigateDownButton(label, text));
    }
    
    public void pressEditCtLogButton(final String label, final String text) {
        clickLink(Page.getEditCtLogButton(label, text));
    }
    
    public void pressSaveEditCtLogButton() {
        clickLink(Page.BUTTON_EDIT_CTLOG);
    }
    
    public void isArrowUpButtonDisabled(final String label, final String text) {
        assertFalse(findElement(Page.getNavigateUpButton(label, text)).isEnabled());
    }

    public void isArrowDownButtonDisabled(final String label, final String text) {
        assertFalse(findElement(Page.getNavigateDownButton(label, text)).isEnabled());
    }
}
