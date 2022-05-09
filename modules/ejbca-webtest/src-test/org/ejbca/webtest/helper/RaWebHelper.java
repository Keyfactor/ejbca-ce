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

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

// TODO JavaDoc
/**
 * RA Web helper class for EJBCA Web Tests.
 *
 */
public class RaWebHelper extends BaseHelper {

    private static final Logger log = Logger.getLogger(RaWebHelper.class);

    public RaWebHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Contains constants and references of the 'RA Web' page.
     */
    public static class Page {
        public static final String PAGE_URI = "/ejbca/ra/";
        public static final String ENDUSER = "ENDUSER";

        static final By BUTTON_MAKE_NEW_REQUEST = By.id("makeRequestButton");
        static final By SELECT_CERTIFICATE_TYPE = By.id("requestTemplateForm:selectEEPOneMenu");
        static final By SELECT_CERTIFICATE_SUBTYPE = By.id("requestTemplateForm:selectCPOneMenu");
        static final By SELECT_CA_TYPE = By.id("requestTemplateForm:selectCAOneMenu");
        static final By SELECT_KEY_ALGORITHM = By.id("requestInfoForm:selectAlgorithmOneMenu");
        static final By SELECT_TOKEN_TYPE = By.id("requestInfoForm:selectTokenOneMenu");
        static final By RADIO_BUTTON_KEY_PAIR_ON_SERVER = By.id("requestTemplateForm:selectKeyPairGeneration:0");
        static final By RADIO_BUTTON_KEY_PAIR_PROVIDED = By.id("requestTemplateForm:selectKeyPairGeneration:1");
        static final By RADIO_BUTTON_KEY_PAIR_POSTPONE = By.id("requestTemplateForm:selectKeyPairGeneration:2");
        static final By LABELS_GROUP_PROVIDE_REQUEST_INFO = By.xpath("//div[@id='requestInfoForm:requestInfoRendered']//label");
        static final By LABEL_COMMON_NAME = By.xpath("//div[@id='requestInfoForm:requestInfoRendered']//label");
        static final By LABELS_GROUP_PROVIDE_USER_CREDENTIALS = By.xpath("//div[@id='requestInfoForm:userCredentialsOuterPanel']//label");
        static final By BUTTON_SHOW_DETAILS = By.xpath("//div[@id='requestTemplateForm:selectRequestTemplateOuterPanel']//input[@value='Show details']");
        static final By TEXTAREA_CERTIFICATE_REQUEST = By.id("keyPairForm:certificateRequest");
        static final By BUTTON_UPLOAD_CSR = By.id("keyPairForm:uploadCsrButton");
        static final By TEXT_ERROR_MESSAGE = By.xpath("//li[@class='errorMessage']");
        static final By TEXT_INFO_MESSAGE = By.xpath("//li[@class='infoMessage']");
        static final By INPUT_NAME_CONSTRAINT_PERMITTED = By.id("requestInfoForm:nameConstraintPermitted");
        static final By INPUT_NAME_CONSTRAINT_EXCLUDED = By.id("requestInfoForm:nameConstraintExcluded");
        static final By INPUT_COMMON_NAME = By.id("requestInfoForm:subjectDn:0:subjectDnField");
        static final By INPUT_ORGANIZATION = By.id("requestInfoForm:subjectDnOptionalFields:0:subjectDnFieldOptional");
        static final By INPUT_COUNTRY = By.id("requestInfoForm:subjectDnOptionalFields:1:subjectDnFieldOptional");

        // Manage Requests
        static final By BUTTON_MENU_MANAGE_REQUESTS = By.id("menuManageRequests");
        static final By BUTTON_TAB_APPROVE_REQUESTS = By.id("manageRequestsForm:tabApproveRequests");
        static final By BUTTON_TAB_PENDING_REQUESTS = By.id("manageRequestsForm:tabPendingRequests");
        static final By BUTTON_DOWNLOAD_PEM = By.id("requestInfoForm:generatePem"); 
        static final By BUTTON_DOWNLOAD_KEYSTORE_PEM = By.id("requestInfoForm:generateKeyStorePem");
        static final By BUTTON_DOWNLOAD_P12 = By.id("requestInfoForm:generateP12");
        static final By BUTTON_DOWNLOAD_JKS = By.id("requestInfoForm:generateJks");
        static final By BUTTON_RESET = By.id("requestInfoForm:resetButton");
        static final By BUTTON_ADD_END_ENTITY = By.id("requestInfoForm:addEndEntity");
        static final By TABLE_REQUESTS = By.id("manageRequestsForm:manageRequestTable");
        static final By TABLE_REQUEST_ROWS = By.xpath("//tbody/tr");
        static final By TABLE_REQUEST_ROW_CELLS = By.xpath(".//td");
        static final By BUTTON_REQUEST_ROW_CELL_REVIEW = By.xpath(".//a[contains(@id, ':viewMoreButton')]");
        static final By BUTTON_REQUEST_APPROVE = By.id("manageRequestForm:commandApprove");
        static final By BUTTON_REQUEST_REJECT = By.id("manageRequestForm:commandReject");
        static final By BUTTON_REQUEST_EDIT = By.id("manageRequestForm:commandEditData");
        static final By INPUT_MANAGE_REQUEST_EDIT_FORM_CN = By.id("manageRequestForm:eeDetails:subjectDistinguishedName:2:subjectDistinguishedNameField");
        static final By INPUT_DNS_NAME = By.id("requestInfoForm:subjectAlternativeNameOptional:0:subjectAltNameOptionalField");
        static final By BUTTON_REQUEST_EDIT_SAVE = By.id("manageRequestForm:commandSaveData");
        static final By TEXT_REQUEST_FORM_SUBJECT_DISTINGUISHED_NAME = By.xpath("//span[contains(@id, ':subjectdn')]");
        static final By TEXT_REQUEST_FORM_APPROVE_MESSAGE = By.id("manageRequestForm:requestApproveMessage");
        static final By INPUT_USERNAME = By.id("requestInfoForm:usernameField");
        static final By INPUT_ENROLLMENTCODE = By.id("requestInfoForm:passwordField");
        static final By INPUT_ENROLLMENTCODE_CONFIRM = By.id("requestInfoForm:passwordConfirmField");
        static final By INPUT_EMAIL = By.id("requestInfoForm:emailField");
        static final By BUTTON_ADD_END_ENDTITY = By.id("requestInfoForm:addEndEntity");
        static final By ENROLL_LABEL_PERMITTED_NAME_CONSTR_REQ = By.xpath("//*[text()=\"Permitted Name Constraints *\"]");
        static final By ENROLL_LABEL_PERMITTED_NAME_CONSTR = By.xpath("//*[text()=\"Permitted Name Constraints\"]");
        static final By ENROLL_LABEL_EXCLUDED_NAME_CONSTR_REQ = By.xpath("//*[text()=\"Excluded Name Constraints *\"]");
        static final By ENROLL_LABEL_EXCLUDED_NAME_CONSTR = By.xpath("//*[text()=\"Excluded Name Constraints\"]");

        // Search End Entities
        static final By BUTTON_MENU_SEARCH_END_ENTITIES = By.xpath(".//a[@href=\"search_ees.xhtml\"]");
        static final By INPUT_SEARCH_END_ENTITES = By.id("contentForm:genericSearchString");
        static final By BUTTON_VIEW_END_ENTITY_SINGLE_RESULT = By.id("contentForm:searchEntityTable:0:viewButton");
        static final By BUTTON_EDIT_END_ENTITY_SINGLE_RESULT = By.id("contentForm:searchEntityTable:0:editButton");
        static final By TABLE_SEARCH_END_ENTITY_RESULT_ROW = By.xpath("//*[@id=\"contentForm:searchEntityTable\"]/tbody/tr");

        // View End Entity
        static final By SECTION_PERMITTED_NAME_CONSTRAINT_VIEW_ENTITY = By.xpath("//*[contains(@id, 'nameConstraintsPermitted')]");
        static final By SECTION_EXCLUDED_NAME_CONSTRAINT_VIEW_ENTITY = By.xpath("//*[contains(@id, 'nameConstraintsExcluded')]");
        static final By EDIT_BUTTON_VIEW_ENTITY = By.xpath("//*[contains(@value, 'Edit')]");
        static final By LABEL_PERMITTED_NAME_CONSTR_REQ = By.xpath("//*[text()=\"Name constraints, permitted *\"]");
        static final By LABEL_PERMITTED_NAME_CONSTR = By.xpath("//*[text()=\"Name constraints, permitted\"]");
        static final By LABEL_EXCLUDED_NAME_CONSTR_REQ = By.xpath("//*[text()=\"Name constraints, excluded *\"]");
        static final By LABEL_EXCLUDED_NAME_CONSTR = By.xpath("//*[text()=\"Name constraints, excluded\"]");
        static final By LABEL_EXCLUDED_NAME_CONSTR_NONE = By.xpath("//*[contains(@id, 'nameConstraintsExcludedNone')]");
        static final By LABEL_PERMITTED_NAME_CONSTR_NONE = By.xpath("//*[contains(@id, 'nameConstraintsPermittedNone')]");

        // Edit End Entity
        static final By INPUT_PERMITTED_NAME_CONSTRAINT_EDIT_ENTITY = By.xpath("//*[contains(@id, 'newNameConstraintPermitted')]");
        static final By INPUT_EXCLUDED_NAME_CONSTRAINT_EDIT_ENTITY = By.xpath("//*[contains(@id, 'newNameConstraintExcluded')]");
        static final By SAVE_BUTTON_EDIT_ENTITY = By.xpath("//*[contains(@value, 'Save')]");
        
        // Containers
        static final By CONTAINER_ENROLL_BUTTONS = By.id("requestInfoForm:enrollButtons");
        static final By CSR_FILE_INPUT_FIELD = By.id("keyPairForm:certificateUploadInput");
        
        // View End Entity and Approval
        static final By TEXT_EMAIL = By.xpath("//*[contains(@id, 'email')]");

        static By getRequestInfoFormSubjectDnSubjectDnField(final int index) {
            return By.id("requestInfoForm:subjectDn:" + index + ":subjectDnField");
        }
    }
    
    /**
     * Opens the 'RA Web' page and asserts the correctness of URI path.
     *
     * @param webUrl the URL of the AdminWeb.
     */
    public void openPage(final String webUrl) {
        openPageByUrlAndAssert(webUrl, Page.PAGE_URI);
    }

    public void makeNewCertificateRequest() throws InterruptedException {
        clickLink(Page.BUTTON_MAKE_NEW_REQUEST);
        TimeUnit.SECONDS.sleep(2);
    }

    /**
     * Clicks the link 'Manage Requests' in the top menu.
     */
    public void clickMenuManageRequests() {
        clickLink(Page.BUTTON_MENU_MANAGE_REQUESTS);
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
    
    public void clickSearchEndEntities(String webUrl) {
        webDriver.get(webUrl + "search_ees.xhtml");
    }

    public void selectCertificateTypeByEndEntityName(final String endEntityProfileName) throws InterruptedException {
        try {
            selectOptionByName(Page.SELECT_CERTIFICATE_TYPE, endEntityProfileName);
        } catch (NoSuchElementException e) {
            final String nameWithDefault = endEntityProfileName + " (default)";
            if (log.isDebugEnabled()) {
                log.debug("Certificate type select item '" + endEntityProfileName + "' was not found, trying with '" + nameWithDefault + "'");
            }
            selectOptionByName(Page.SELECT_CERTIFICATE_TYPE, nameWithDefault);            
        }       
        TimeUnit.SECONDS.sleep(2);
    }
    
    public void selectCertificateSubType(final String certProfileName) throws InterruptedException {
        try {
            selectOptionByName(Page.SELECT_CERTIFICATE_SUBTYPE, certProfileName);
        } catch (NoSuchElementException e) {
            final String nameWithDefault = certProfileName + " (default)";
            if (log.isDebugEnabled()) {
                log.debug("Certificate subtype select item '" + certProfileName + "' was not found, trying with '" + nameWithDefault + "'");
            }
            selectOptionByName(Page.SELECT_CERTIFICATE_SUBTYPE, nameWithDefault);            
        }       
        TimeUnit.SECONDS.sleep(2);
    }

    public void selectCertificationAuthorityByName(final String ca) throws InterruptedException {
        try {
            selectOptionByName(Page.SELECT_CA_TYPE, ca);
        } catch (NoSuchElementException e) {
            final String nameWithDefault = ca + " (default)";
            if (log.isDebugEnabled()) {
                log.debug("CA select item '" + ca + "' was not found, trying with '" + nameWithDefault + "'");
            }
            selectOptionByName(Page.SELECT_CA_TYPE, nameWithDefault);
        }
        TimeUnit.SECONDS.sleep(2);
    }

    public void selectKeyAlgorithm(final String keyAlgorithm) {
        selectOptionByName(Page.SELECT_KEY_ALGORITHM, keyAlgorithm);
    }

    public void selectTokenType(final String tokenType) {
        selectOptionByName(Page.SELECT_TOKEN_TYPE, tokenType);
    }
    
    public void selectKeyPairGenerationOnServer() throws InterruptedException {
        clickLink(Page.RADIO_BUTTON_KEY_PAIR_ON_SERVER);
        TimeUnit.SECONDS.sleep(2);
    }

    public void selectKeyPairGenerationPostpone() throws InterruptedException {
        clickLink(Page.RADIO_BUTTON_KEY_PAIR_POSTPONE);
        TimeUnit.SECONDS.sleep(2);
    }
    
    public void selectKeyPairGenerationProvided() throws InterruptedException {
        clickLink(Page.RADIO_BUTTON_KEY_PAIR_PROVIDED);
        TimeUnit.SECONDS.sleep(2);
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
        assertEquals("Unexpected number of fields under 'Provide User Credentials'", 5, provideUserCredentialsWebElements.size());
        assertEquals("Expected the label to have the value 'Username *'", "Username *", provideUserCredentialsWebElements.get(0).getText());
        assertEquals("Expected the label to have the value 'Enrollment code *'", "Enrollment code *", provideUserCredentialsWebElements.get(1).getText());
        assertEquals("Expected the label to have the value 'Confirm enrollment code *'", "Confirm enrollment code *", provideUserCredentialsWebElements.get(2).getText());
        assertEquals("Expected the label to have the value 'Batch generation'", "Batch generation", provideUserCredentialsWebElements.get(3).getText());
        assertEquals("Expected the label to have the value 'Email'", "Email", provideUserCredentialsWebElements.get(4).getText());
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

    public void assertTokenTypeSelection(final boolean isEnabled) {
        final WebElement tokenTypeSelectionWebElement = findElement(Page.SELECT_TOKEN_TYPE);
        assertNotNull("Token type selection was not found.", tokenTypeSelectionWebElement);
        assertEquals("Token type selection was not restricted (enabled = [" + isEnabled + "])", isEnabled, tokenTypeSelectionWebElement.isEnabled());
    }

    public void assertKeyAlgorithmSelection(final String keyAlgorithmValue, final boolean isEnabled) {
        final WebElement keyAlgorithmSelectionWebElement = findElement(Page.SELECT_KEY_ALGORITHM);
        assertNotNull("Key Algorithm selection was not found.", keyAlgorithmSelectionWebElement);
        assertEquals("Key Algorithm selection is wrong", keyAlgorithmValue, keyAlgorithmSelectionWebElement.getText());
        assertEquals("Key Algorithm selection was not restricted (enabled = [" + isEnabled + "])", isEnabled, keyAlgorithmSelectionWebElement.isEnabled());
    }
    
    /**
     * Click to add endEndtity
     */
    public void clickAddEndEntityButton() {
        clickLink(Page.BUTTON_ADD_END_ENDTITY);
    }

    public void fillCsrFilename(final String inputFilename) {
        fillInput(Page.CSR_FILE_INPUT_FIELD, inputFilename);
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
        // Add a timeout to load enroll buttons pane before click
        findElement(Page.CONTAINER_ENROLL_BUTTONS);
        clickLink(Page.BUTTON_DOWNLOAD_PEM);
    }

    /**
     * Click add end entity for postponed requests
     */
    public void clickAddEndEntity() {
        // Add a timeout to load enroll buttons pane before click
        findElement(Page.CONTAINER_ENROLL_BUTTONS);
        clickLink(Page.BUTTON_ADD_END_ENTITY);
    }

    /**
     * Click to "Download PEM" button in requestInfoForm form.
     */
    public void clickDownloadKeystorePem() { 
        clickLink(Page.BUTTON_DOWNLOAD_KEYSTORE_PEM);
    }

    /**
     * Click to download jks
     */
    public void clickDownloadJks() {
        // Add a timeout to load enroll buttons pane before click
        findElement(Page.CONTAINER_ENROLL_BUTTONS);
        clickLink(Page.BUTTON_DOWNLOAD_JKS);
    }

    /**
     * Click to "Download PKCS#12" button in the requestInfoform form.
     * <p>
     * This method works in the 'Enroll - Make New Request' workflow.
     */
    public void clickDownloadPkcs12(){
        // Add a timeout to load enroll buttons pane before click
        findElement(Page.CONTAINER_ENROLL_BUTTONS);
        clickLink(Page.BUTTON_DOWNLOAD_P12);
    }

    /**
     * Click to reset Make Request page
     */

    public void clickMakeRequestReset() {
        clickLink(Page.BUTTON_RESET);
    }
    
    public void clickViewEndEntity() {
        clickLink(Page.BUTTON_VIEW_END_ENTITY_SINGLE_RESULT);
    }
    
    public void clickEditInViewEndEntity() {
        clickLink(Page.EDIT_BUTTON_VIEW_ENTITY);
    }
    
    public void clickSaveInEditEndEntity() {
        clickLink(Page.SAVE_BUTTON_EDIT_ENTITY);
    }

    public void assertCsrUploadError() {
        final WebElement errorMessageWebElement = findElement(Page.TEXT_ERROR_MESSAGE);
        assertNotNull("No/wrong error message displayed when uploading forbidden CSR.", errorMessageWebElement);
        assertTrue("Error message does not match.", errorMessageWebElement.getText().contains("The key algorithm 'RSA_2048' is not available"));
    }


    public void assertErrorMessageContains(final String noErrorMessage, final String errorMessage) {
        final WebElement errorMessageWebElement = findElement(Page.TEXT_ERROR_MESSAGE);
        assertNotNull(noErrorMessage, errorMessageWebElement);
        assertTrue("Error message does not match. Should contains '" + errorMessage + "', but was '" + errorMessageWebElement.getText() + "'",
                errorMessageWebElement.getText().contains(errorMessage));
    }

    public void assertInfoMessageContains(final String noInfoMessage, final String infoMessage) {
        final WebElement infoMessageWebElement = findElement(Page.TEXT_INFO_MESSAGE);
        assertNotNull(noInfoMessage, infoMessageWebElement);
        assertTrue("Info message does not match. Should contains '" + infoMessage + "', but was '" + infoMessageWebElement.getText() + "'",
                infoMessageWebElement.getText().contains(infoMessage));
    }

    public void assertSearchTableResult(int number){
        final List<WebElement> searchResultRows = findElements(Page.TABLE_SEARCH_END_ENTITY_RESULT_ROW);
        assertEquals("Wrong number of search results in end entity search: ", number, searchResultRows.size());
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
     * Asserts the email exists and it's content.
     */
    public void assertEmailContent(String email) {
        final WebElement emailWebElement = findElement(Page.TEXT_EMAIL);
        assertNotNull("Cannot find end entity email.", emailWebElement);
        assertTrue("End entity or Approval data email does not match. Should contains '" + email 
                + "', but was '" + emailWebElement.getText() + "'",
                emailWebElement.getText().contains(email));
        
    }

    /**
     * Triggers the link 'Edit data' in request review form.
     */
    public void triggerRequestEditLink() {
        clickLink(Page.BUTTON_REQUEST_EDIT);
    }    
  
    public void fillUsernameProvideUserCredentials(String userName) {
        fillTextarea(Page.INPUT_USERNAME,userName);
        
    }

    public void fillClearCsrText(final String csr) {
        fillTextarea(Page.TEXTAREA_CERTIFICATE_REQUEST, csr);
    }
    
    /**
     * Fills the 'CN, Common Name' with text in make request edit form.
     * 
     * NB: This requires the certificate profile to be created in a way, that "common name" appears as the 0th element in the list!
     * (Otherwise you are unable to find it by 'INPUT_MAKE_REQUEST_EDIT_FORM_DNATTRIBUTE0' selector)
     * Suggestion: use fillDnAttributeX methods instead! 
     *  
     * @param cnText Common Name.
     */
    public void fillMakeRequestEditCommonName(final String cnText) {
        fillInput(Page.getRequestInfoFormSubjectDnSubjectDnField(0), cnText);
    }
    
    /**
     * Fills the 'CN, Common Name' with text in manage request edit form.
     *
     * @param cnText Common Name.
     */
    public void fillManageRequestEditCommonName(final String cnText) {
        fillInput(Page.INPUT_MANAGE_REQUEST_EDIT_FORM_CN, cnText);
    }

    /**
     * Fills the 'DNS Name' with text in the request edit form.
     *
     * @param cnDnsName DNS name
     */
    public void fillDnsName(final String cnDnsName) {
        fillInput(Page.INPUT_DNS_NAME, cnDnsName);
    }
    
    /**
     * The "Subject DN Attributes" in the "Provide request info" section are identified like follows:
     * requestInfoForm:subjectDn:0:subjectDnField
     * requestInfoForm:subjectDn:1:subjectDnField
     * ...
     * 
     * This method fills the 0th element with the value provided by 'attributeValue' input param.
     *
     * @param dnAttributeIndex attribute's index
     * @param attributeValue value
     */
    public void fillDnAttribute(final int dnAttributeIndex, final String attributeValue) {
        fillInput(Page.getRequestInfoFormSubjectDnSubjectDnField(dnAttributeIndex), attributeValue);
    }

    /**
     * Fills the "User Credentials" section with username and enrollment code. 
     * Also fills the enrollment code confirmation box with the same enrollment code value
     * 
     * @param username username
     * @param enrollmentCode enrollment code
     */
    public void fillCredentials(final String username, final String enrollmentCode) {
        fillInput(Page.INPUT_USERNAME, username);
        fillInput(Page.INPUT_ENROLLMENTCODE, enrollmentCode);
        fillInput(Page.INPUT_ENROLLMENTCODE_CONFIRM, enrollmentCode);
    }
    
    public void fillCredentialEmail(final String email) {
        fillInput(Page.INPUT_EMAIL, email);
    }
    //requestInfoForm:emailField
    
    public void fillRequiredSubjectDNAttributes(String commonName) {
        fillInput(Page.INPUT_COMMON_NAME, commonName);
    }

    public void  verifyCommonNameValue(String commonName, String errorMessage) {
        verifyInputValue(Page.INPUT_COMMON_NAME, commonName, errorMessage);
    }

    public void  verifyOrganizationValue(String organization, String errorMessage) {
        verifyInputValue(Page.INPUT_ORGANIZATION, organization, errorMessage);
    }

    public void  verifyCountryValue(String country, String errorMessage) {
        verifyInputValue(Page.INPUT_COUNTRY, country, errorMessage);
    }

    public void  verifyInputValue(final By inputId, String value, String errorMessage) {
        assertEquals(
                errorMessage,
                value,
                getElementValue(inputId)
        );
    }
    
    /**
     * Fills the username 
     * 
     * @param username username
     */
    public void fillUsername(final String username) {
        fillInput(Page.INPUT_USERNAME, username);
    }
    
    public void fillNameConstraintPermitted(final String nameConstraintPermitted) {
        fillInput(Page.INPUT_NAME_CONSTRAINT_PERMITTED, nameConstraintPermitted);
    }
    
    public void fillNameConstraintExcluded(final String nameConstraintExcluded) {
        fillInput(Page.INPUT_NAME_CONSTRAINT_EXCLUDED, nameConstraintExcluded);
    }
    
    public void fillSearchEndEntity(final String endEntityName) {
        fillInput(Page.INPUT_SEARCH_END_ENTITES, endEntityName);
    }
    
    public void editNameConstraintPermitted(final String nameConstraintPermitted) {
        fillInput(Page.INPUT_PERMITTED_NAME_CONSTRAINT_EDIT_ENTITY, nameConstraintPermitted);
    }
    
    public void editNameConstraintExcluded(final String nameConstraintExcluded) {
        fillInput(Page.INPUT_EXCLUDED_NAME_CONSTRAINT_EDIT_ENTITY, nameConstraintExcluded);
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
    
    public String getPermittedNameConstraint() {
        return getElementText(Page.SECTION_PERMITTED_NAME_CONSTRAINT_VIEW_ENTITY);
    }
    
    public String getExcludedNameConstraint() {
        return getElementText(Page.SECTION_EXCLUDED_NAME_CONSTRAINT_VIEW_ENTITY);
    }
    
    public String getErrorMessage() {
        return getElementText(Page.TEXT_ERROR_MESSAGE);
    }
    
    public void assertErrorMessageAppears(final String expectedErrorMessage, final String noElementMessage, final String assertMessage) {
        assertAllErrorMessagesAppear(new String[]{expectedErrorMessage}, noElementMessage, assertMessage);
    }
    
    /**
     * Assert the existence of a file at a specific location
     *
     * @param filePath
     */
    public void assertDownloadedFileExits(final String filePath) {        
        assertTrue(filePath, Files.exists(Paths.get(filePath)));
    }

    public void assertRequiredPermittedConstraintDisplayed(){
        assertElementDisplayed(Page.ENROLL_LABEL_PERMITTED_NAME_CONSTR_REQ, "required permitted name constraint");
    }

    public void assertPermittedConstraintDisplayed(){
        assertElementDisplayed(Page.ENROLL_LABEL_PERMITTED_NAME_CONSTR, "permitted name constraint");
    }

    public void assertPermittedConstraintNotDisplayed(){
        assertElementNotDisplayed(Page.ENROLL_LABEL_PERMITTED_NAME_CONSTR, "permitted name constraint");
    }

    public void assertRequiredExcludedConstraintDisplayed(){
        assertElementDisplayed(Page.ENROLL_LABEL_EXCLUDED_NAME_CONSTR_REQ, "required excluded name constraint");
    }

    public void assertExcludedConstraintDisplayed(){
        assertElementDisplayed(Page.ENROLL_LABEL_EXCLUDED_NAME_CONSTR, "excluded name constraint");
    }

    public void assertExcludedConstraintNotDisplayed(){
        assertElementNotDisplayed(Page.ENROLL_LABEL_EXCLUDED_NAME_CONSTR, "excluded name constraint");
    }

    public void assertRequiredPermittedConstraintDisplayedOnViewPage(){
        assertElementDisplayed(Page.LABEL_PERMITTED_NAME_CONSTR_REQ, "required permitted name constraint");
    }

    public void assertPermittedConstraintDisplayedOnViewPage(){
        assertElementDisplayed(Page.LABEL_PERMITTED_NAME_CONSTR, "permitted name constraint");
    }
    public void assertRequiredExcludedConstraintDisplayedOnViewPage(){
        assertElementDisplayed(Page.LABEL_EXCLUDED_NAME_CONSTR_REQ, "required excluded name constraint");
    }

    public void assertExcludedConstraintDisplayedOnViewPage(){
        assertElementDisplayed(Page.LABEL_EXCLUDED_NAME_CONSTR, "excluded name constraint");
    }

    public void assertExcludedConstraintNoneDisplayed(){
        assertElementDisplayed(Page.LABEL_EXCLUDED_NAME_CONSTR_NONE, "none excluded name constraint");
    }

    public void assertPermittedConstraintNoneDisplayed(){
        assertElementDisplayed(Page.LABEL_PERMITTED_NAME_CONSTR_NONE, "none permitted name constraint");
    }
}
