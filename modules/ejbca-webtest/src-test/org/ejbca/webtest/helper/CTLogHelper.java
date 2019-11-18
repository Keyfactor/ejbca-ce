package org.ejbca.webtest.helper;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
//import org.openqa.selenium.support.pagefactory.ByChained;

import java.io.File;
import java.util.List;

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
        static final By TABLE = By.xpath(".//table[@class='grid ctlogTable']/tbody");

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

    public void assertIsTableRowsCorrectOrder(){
        final List<WebElement> approvalSteps = findElements(Page.TABLE);
    }

}
