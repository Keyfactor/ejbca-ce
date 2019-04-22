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

import java.util.List;

import static org.junit.Assert.*;

// TODO JavaDoc
/**
 * RA Web helper class for EJBCA Web Tests.
 *
 * @version $Id$
 */
public class RaWebHelper extends BaseHelper {

    public RaWebHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Contains constants and references of the 'RA Web' page.
     */
    public static class Page {
        public static final String PAGE_URI = "/ejbca/ra/";

        static final By BUTTON_MAKE_NEW_REQUEST = By.id("makeRequestButton");
        static final By SELECT_CERTIFICATE_TYPE = By.id("requestTemplateForm:selectEEPOneMenu");
        static final By SELECT_CERTIFICATE_SUBTYPE = By.id("requestTemplateForm:selectCPOneMenu");
        static final By SELECT_CA_TYPE = By.id("requestTemplateForm:selectCAOneMenu");
        static final By SELECT_KEY_ALGORITHM = By.id("requestInfoForm:selectAlgorithmOneMenu");
        static final By RADIO_BUTTON_KEY_PAIR_ON_SERVER = By.id("requestTemplateForm:selectKeyPairGeneration:0");
        static final By RADIO_BUTTON_KEY_PAIR_PROVIDED = By.id("requestTemplateForm:selectKeyPairGeneration:1");
        static final By LABELS_GROUP_PROVIDE_REQUEST_INFO = By.xpath("//div[@id='requestInfoForm:requestInfoRendered']//label");
        static final By LABEL_COMMON_NAME = By.xpath("//div[@id='requestInfoForm:requestInfoRendered']//label");
        static final By LABELS_GROUP_PROVIDE_USER_CREDENTIALS = By.xpath("//div[@id='requestInfoForm:userCredentialsOuterPanel']//label");
        static final By BUTTON_SHOW_DETAILS = By.xpath("//div[@id='requestTemplateForm:selectRequestTemplateOuterPanel']//input[@value='Show details']");
        static final By TEXTAREA_CERTIFICATE_REQUEST = By.id("keyPairForm:certificateRequest");
        static final By BUTTON_UPLOAD_CSR = By.id("keyPairForm:uploadCsrButton");
        static final By TEXT_ERROR_MESSAGE = By.xpath("//li[@class='errorMessage']");
        // Manage Requests
        static final By BUTTON_TAB_CONFIRM_REQUESTS = By.id("requestInfoForm:confirmRequestButton");
        static final By BUTTON_MENU_MANAGE_REQUESTS = By.id("menuManageRequests");
        static final By BUTTON_TAB_APPROVE_REQUESTS = By.id("manageRequestsForm:tabApproveRequests");
        static final By BUTTON_TAB_PENDING_REQUESTS = By.id("manageRequestsForm:tabPendingRequests");
        static final By BUTTON_DOWNLOAD_PEM = By.id("requestInfoForm:generatePem");
        static final By TABLE_REQUESTS = By.id("manageRequestsForm:manageRequestTable");
        static final By TABLE_REQUEST_ROWS = By.xpath("//tbody/tr");
        static final By TABLE_REQUEST_ROW_CELLS = By.xpath(".//td");
        static final By BUTTON_REQUEST_ROW_CELL_REVIEW = By.xpath(".//a[contains(@id, ':viewMoreButton')]");
        static final By BUTTON_REQUEST_APPROVE = By.id("manageRequestForm:commandApprove");
        static final By BUTTON_REQUEST_REJECT = By.id("manageRequestForm:commandReject");
        static final By BUTTON_REQUEST_EDIT = By.id("manageRequestForm:commandEditData");
        static final By INPUT_REQUEST_EDIT_FORM_CN = By.id("manageRequestForm:eeDetails:subjectDistinguishedName:2:subjectDistinguishedNameField");
        static final By INPUT_DNS_NAME = By.id("requestInfoForm:subjectAlternativeName:0:subjectAltNameField");
        static final By BUTTON_REQUEST_EDIT_SAVE = By.id("manageRequestForm:commandSaveData");
        static final By TEXT_REQUEST_FORM_SUBJECT_DISTINGUISHED_NAME = By.xpath("//span[contains(@id, ':subjectdn')]");
        static final By TEXT_REQUEST_FORM_APPROVE_MESSAGE = By.id("manageRequestForm:requestApproveMessage");
    }

    /**
     * Opens the 'RA Web' page and asserts the correctness of URI path.
     *
     * @param webUrl the URL of the AdminWeb.
     */
    public void openPage(final String webUrl) {
        openPageByUrlAndAssert(webUrl, Page.PAGE_URI);
    }

    public void makeNewCertificateRequest() {
        clickLink(Page.BUTTON_MAKE_NEW_REQUEST);
    }

    /**
     * Clicks the link 'Manage Requests' in the top menu.
     */
    public void clickMenuManageRequests() {
        clickLink(Page.BUTTON_MENU_MANAGE_REQUESTS);
    }

    public void clickConfirmRequest() {
        clickLink(Page.BUTTON_TAB_CONFIRM_REQUESTS);
    }

    /**
     * Clicks the tab 'To Approve'.
     */
    public void clickTabApproveRequests() {
        clickLink(Page.BUTTON_TAB_APPROVE_REQUESTS);
    }

    /**
     * Clicks the tab 'Pending Approval'.
     */
    public void clickTabPendingRequests() {
        clickLink(Page.BUTTON_TAB_PENDING_REQUESTS);
    }

    public void selectCertificateTypeByEndEntityName(final String endEntityProfileName) {
        selectOptionByName(Page.SELECT_CERTIFICATE_TYPE, endEntityProfileName);
    }

    public void selectCertificationAuthorityByName(final String ca) {
        selectOptionByName(Page.SELECT_CA_TYPE, ca);
    }

    public void selectKeyPairGenerationOnServer() {
        clickLink(Page.RADIO_BUTTON_KEY_PAIR_ON_SERVER);
    }

    public void selectKeyPairGenerationProvided() {
        clickLink(Page.RADIO_BUTTON_KEY_PAIR_PROVIDED);
    }

    public void assertCorrectProvideRequestInfoBlock() {
        final List<WebElement> provideRequestInfoWebElements = findElements(Page.LABELS_GROUP_PROVIDE_REQUEST_INFO);
        assertEquals("Unexpected number of fields under 'Provide request info'", 1, provideRequestInfoWebElements.size());
        final WebElement cnWebElement = findElement(Page.LABEL_COMMON_NAME);
        assertNotNull("Common Name label was not found.", cnWebElement);
        assertEquals(
                "Expected the label to have the value 'CN, Common Name *'",
                "CN, Common Name *",
                cnWebElement.getText()
        );
    }

    public void assertCorrectProvideUserCredentialsBlock() {
        final List<WebElement> provideUserCredentialsWebElements = findElements(Page.LABELS_GROUP_PROVIDE_USER_CREDENTIALS);
        assertEquals("Unexpected number of fields under 'Provide User Credentials'", 4, provideUserCredentialsWebElements.size());
        assertEquals("Expected the label to have the value 'Username'", "Username", provideUserCredentialsWebElements.get(0).getText());
        assertEquals("Expected the label to have the value 'Enrollment code'", "Enrollment code", provideUserCredentialsWebElements.get(1).getText());
        assertEquals("Expected the label to have the value 'Confirm enrollment code'", "Confirm enrollment code", provideUserCredentialsWebElements.get(2).getText());
        assertEquals("Expected the label to have the value 'Email'", "Email", provideUserCredentialsWebElements.get(3).getText());
    }

    public void clickShowDetailsButton() {
        clickLink(Page.BUTTON_SHOW_DETAILS);
    }

    public void assertCertificateProfileSelection(final String certificateProfileValue, final boolean isEnabled) {
        final WebElement certificateProfileSelectionWebElement = findElement(Page.SELECT_CERTIFICATE_SUBTYPE);
        assertNotNull("Certificate Profile selection was not found", certificateProfileSelectionWebElement);
        assertEquals("Certificate Profile selection is wrong", certificateProfileValue, certificateProfileSelectionWebElement.getText());
        assertEquals("Certificate Profile selection was not restricted (enabled = [" + isEnabled + "])", isEnabled, certificateProfileSelectionWebElement.isEnabled());
    }

    public void assertKeyAlgorithmSelection(final String keyAlgorithmValue, final boolean isEnabled) {
        final WebElement keyAlgorithmSelectionWebElement = findElement(Page.SELECT_KEY_ALGORITHM);
        assertNotNull("Key Algorithm selection was not found.", keyAlgorithmSelectionWebElement);
        assertEquals("Key Algorithm selection is wrong", keyAlgorithmValue, keyAlgorithmSelectionWebElement.getText());
        assertEquals("Key Algorithm selection was not restricted (enabled = [" + isEnabled + "])", isEnabled, keyAlgorithmSelectionWebElement.isEnabled());
    }

    public void fillClearCsrText(final String csr) {
        fillTextarea(Page.TEXTAREA_CERTIFICATE_REQUEST, csr, true);
    }

    /**
     * Click to upload Csr
     */
    public void clickUploadCsrButton() {
        clickLink(Page.BUTTON_UPLOAD_CSR);
    }

    /**
     * Click to download pem
     */

    public void clickDownloadPem() {
        clickLink(Page.BUTTON_DOWNLOAD_PEM);
    }

    public void assertCsrUploadError() {
        final WebElement errorMessageWebElement = findElement(Page.TEXT_ERROR_MESSAGE);
        assertNotNull("No/wrong error message displayed when uploading forbidden CSR.", errorMessageWebElement);
        assertTrue("Error message does not match.", errorMessageWebElement.getText().contains("The key algorithm 'RSA_2048' is not available"));
    }


    public void assertErrorMessageExists(final String noErrorMessage, final String errorMessage) {
        final WebElement errorMessageWebElement = findElement(Page.TEXT_ERROR_MESSAGE);
        assertNotNull(noErrorMessage, errorMessageWebElement);
        assertEquals("Error message does not match.", errorMessageWebElement.getText(), errorMessage);
    }

    /**
     * Returns a row of request (array of WebElements containing row cells) identified by caName (cell 3), actionType (cell 4),
     * endEntityName (cell 5) and status (cell 7) or null if the row is not found.
     *
     * @param caName CA name.
     * @param actionType type.
     * @param endEntityName end entity name.
     * @param status status.
     *
     * @return The row of request or null.
     */
    public List<WebElement> getRequestsTableRow(final String caName, final String actionType, final String endEntityName, final String status) {
        final WebElement pendingApprovalRequestsTable = findElement(Page.TABLE_REQUESTS);
        final List<WebElement> pendingApprovalRequestsRows = findElements(pendingApprovalRequestsTable, Page.TABLE_REQUEST_ROWS);
        for(WebElement pendingRequestsTableRow : pendingApprovalRequestsRows) {
            final List<WebElement> pendingApprovalRequestsRowCells = findElements(pendingRequestsTableRow, Page.TABLE_REQUEST_ROW_CELLS);
            int pendingApprovalRequestsRowCellIndex = 0;
            boolean foundCaName = false;
            boolean foundActionType = false;
            boolean foundEndEntityName = false;
            boolean foundStatus = false;
            for (WebElement pendingRequestsTableRowCell : pendingApprovalRequestsRowCells) {
                final String pendingRequestsTableRowCellText = pendingRequestsTableRowCell.getText();
                // CA
                if(pendingApprovalRequestsRowCellIndex == 2 && caName.equals(pendingRequestsTableRowCellText)) {
                    foundCaName = true;
                }
                // Type
                else if(pendingApprovalRequestsRowCellIndex == 3 && actionType.equals(pendingRequestsTableRowCellText)) {
                    foundActionType = true;
                }
                // Name
                else if(pendingApprovalRequestsRowCellIndex == 4 && endEntityName.equals(pendingRequestsTableRowCellText)) {
                    foundEndEntityName = true;
                }
                // Request Status
                else if(pendingApprovalRequestsRowCellIndex == 6 && status.equals(pendingRequestsTableRowCellText)) {
                    foundStatus = true;
                }
                if(foundCaName && foundActionType && foundEndEntityName && foundStatus) {
                    return pendingApprovalRequestsRowCells;
                }
                pendingApprovalRequestsRowCellIndex++;
            }
        }
        return null;
    }

    /**
     * Asserts the row of request is not null.
     *
     * @param requestRow the row of pending approval requests (array of WebElements containing row cells).
     */
    public void assertHasRequestRow(final List<WebElement> requestRow) {
        assertNotNull("Cannot find a row in Pending Approvals table.", requestRow);
    }

    /**
     * Returns the id of request within the row.
     *
     * @param requestRow the row of request (array of WebElements containing row cells).
     *
     * @see #getRequestsTableRow(String, String, String, String)
     *
     * @return The id of approval request or -1.
     */
    public int getRequestIdFromRequestRow(final List<WebElement> requestRow) {
        if(requestRow != null && !requestRow.isEmpty()) {
            final String requestRowCellText = requestRow.get(0).getText();
            return Integer.parseInt(requestRowCellText);
        }
        return -1;
    }

    /**
     * Triggers the 'Review' link within the row.
     *
     * @param requestRow the row of request (array of WebElements containing row cells).
     */
    public void triggerRequestReviewLinkFromRequestRow(final List<WebElement> requestRow) {
        if(requestRow != null && !requestRow.isEmpty()) {
            final WebElement requestRowCellContainer = requestRow.get(7);
            final WebElement reviewLink = findElement(requestRowCellContainer, Page.BUTTON_REQUEST_ROW_CELL_REVIEW);
            clickLink(reviewLink);
        }
        else {
            fail("Please check your test scenario action, this action cannot be applied.");
        }
    }

    /**
     * Asserts the 'Approve' button exists.
     */
    public void assertRequestApproveButtonExists() {
        assertElementExists(Page.BUTTON_REQUEST_APPROVE, "Cannot find 'Approve' button.");
    }

    /**
     * Asserts the 'Approve' button does not exist.
     */
    public void assertRequestApproveButtonDoesNotExist() {
        assertElementDoesNotExist(Page.BUTTON_REQUEST_APPROVE, "Found 'Approve' button.");
    }

    /**
     * Triggers the 'Approve' button.
     */
    public void triggerRequestApproveButton() {
        clickLink(Page.BUTTON_REQUEST_APPROVE);
    }

    /**
     * Asserts the 'Reject' button exists.
     */
    public void assertRequestRejectButtonExists() {
        assertElementExists(Page.BUTTON_REQUEST_REJECT, "Cannot find 'Reject' button.");
    }

    /**
     * Asserts the 'Reject' button does not exist.
     */
    public void assertRequestRejectButtonDoesNotExist() {
        assertElementDoesNotExist(Page.BUTTON_REQUEST_REJECT, "Found 'Reject' button.");
    }

    /**
     * Triggers the link 'Edit data' in request review form.
     */
    public void triggerRequestEditLink() {
        clickLink(Page.BUTTON_REQUEST_EDIT);
    }

    /**
     * Fills the 'CN, Common Name' with text in request edit form.
     *
     * @param cnText Common Name.
     */
    public void fillRequestEditCommonName(final String cnText) {
        fillInput(Page.INPUT_REQUEST_EDIT_FORM_CN, cnText);
    }

    /**
     * Fills the 'DNS Name' with text in the request edit form.
     *
     * @param cnDnsName
     */
    public void fillDnsName(final String cnDnsName) {
        fillInput(Page.INPUT_DNS_NAME, cnDnsName);
    }

    /**
     * Triggers the link 'Save data' in request review form.
     */
    public void triggerRequestEditSaveForm() {
        clickLink(Page.BUTTON_REQUEST_EDIT_SAVE);
    }

    /**
     * Asserts the 'Subject Distinguished Name' text has text value.
     *
     * @param textValue text value.
     */
    public void assertSubjectDistinguishedNameHasText(final String textValue) {
        assertEquals(
                "'Subject Distinguished Name' mismatch.",
                textValue,
                getElementText(Page.TEXT_REQUEST_FORM_SUBJECT_DISTINGUISHED_NAME)
        );
    }

    /**
     * Asserts the 'Approve' text has text value.
     *
     * @param textValue text value.
     */
    public void assertApproveMessageHasText(final String textValue) {
        assertEquals(
                "'Approve' message mismatch.",
                textValue,
                getElementText(Page.TEXT_REQUEST_FORM_APPROVE_MESSAGE)
        );
    }

    /**
     * Asserts the 'Approve Message' does not appear.
     */
    public void assertApproveMessageDoesNotExist() {
                assertElementDoesNotExist(Page.TEXT_REQUEST_FORM_APPROVE_MESSAGE, "There was Approve message displayed upon creation of EE");
    }


}
