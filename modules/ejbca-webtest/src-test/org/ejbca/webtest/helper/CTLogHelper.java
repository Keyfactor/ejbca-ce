package org.ejbca.webtest.helper;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.io.File;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class CTLogHelper extends BaseHelper {
    public CTLogHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    public static class Page {
        static final By LOG_URL_INPUT_FIELD = By.xpath("//input[@name='ctlogsform:j_idt380']");
        static final By PUBLIC_KEY_INPUT_FIELD = By.xpath("//input[@type='file'][@name='ctlogsform:currentCTLogKeyFile']");
        static final By TIMEOUT_INPUT_FIELD = By.xpath("//input[@name='ctlogsform:j_idt383']");
        static final By LABEL_INPUT_FIELD = By.xpath("//input[@name='ctlogsform:j_idt384']");
        static final By BUTTON_ADD = By.xpath("//input[@type='submit'][@name='ctlogsform:j_idt385']");
        static final By TABLE_ROW_DATA = By.xpath("//table[@class='grid ctlogTable']/tbody/tr/td[1]/span");
        static final By ARROW_DOWN_BUTTON = By.xpath("//input[@type='submit'][@name='ctlogsform:j_idt348:1:j_idt353:0:j_idt372'][@title='Move Down']");
        static final By ARROW_UP_BUTTON = By.xpath("//input[@type='submit'][@name='ctlogsform:j_idt348:1:j_idt353:1:j_idt371'][@title='Move Up']");
        static final By ARROW_DOWN_BUTTON_DISABLED = By.xpath("//input[@type='submit'][@name='ctlogsform:j_idt348:1:j_idt353:1:j_idt372'][@title='Move Down']");
        static final By ARROW_UP_BUTTON_DISABLED = By.xpath("//input[@type='submit'][@name='ctlogsform:j_idt348:1:j_idt353:0:j_idt371'][@title='Move Up']");

        static By getLabelTextFromTable(final String text) {
            return By.xpath("//tr/td/h3[contains(text(), '" + text + "')]");
        }

        static By getLogURLTextFromTableRow(final String rowText) {
            return By.xpath("//tr/td/table[@class='grid ctlogTable']/tbody/tr/td/span[@title='Log URL'][contains(text(), '" + rowText + "')]");
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

    public void addCertificateTransparencyLog() {
        clickLink(Page.BUTTON_ADD);
    }

    public void assertIsTableAndRowExists(final String matchLabelWith, final String matchRowWith) {
        assertElementExists(Page.getLabelTextFromTable(matchLabelWith), "Element label:" + matchLabelWith + " does not exist from table.");
        assertElementExists(Page.getLogURLTextFromTableRow(matchRowWith), "Element " + matchRowWith + " does not exist from table row.");
    }

    public void assertIsTableRowsCorrectOrder(int rowNum, String rowData){
        final List<WebElement> tableRows = findElements(Page.TABLE_ROW_DATA);
        assertEquals(tableRows.get(rowNum).getText(), rowData);
    }

    public void pressArrowUpButton(){
        clickLink(Page.ARROW_UP_BUTTON);
    }

    public void pressArrowDownButton(){
        clickLink(Page.ARROW_DOWN_BUTTON);
    }

    public void isArrowUpButtonDisabled() {
        assertFalse(findElement(Page.ARROW_UP_BUTTON_DISABLED).isEnabled());
    }

    public void isArrowDownButtonDisabled() {
        assertFalse(findElement(Page.ARROW_DOWN_BUTTON_DISABLED).isEnabled());
    }
}
