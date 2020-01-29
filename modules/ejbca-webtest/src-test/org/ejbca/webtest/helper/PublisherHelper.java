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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Collection;
import java.util.List;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

/**
 * Helper class used in publisher page tests.
 * 
 * @version $Id$
 *
 */
public class PublisherHelper extends BaseHelper {
    
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/ca/editpublishers/listpublishers.xhtml";
        static final By PAGE_LINK = By.id("caEditpublishers");
        
        // Buttons
        static final By BUTTON_ADD_PUBLISHER = By.id("listPublishers:addButton");
        static final By BUTTON_CLONE_PUBLISHER = By.id("listPublishers:cloneButton");
        static final By BUTTON_RENAME_PUBLISHER = By.id("listPublishers:renameButton");
        static final By BUTTON_DELETE_PUBLISHER = By.id("listPublishers:deleteButton");
        static final By BUTTON_EDIT_PUBLISHER = By.id("listPublishers:editButton");
        static final By BUTTON_SAVE_AND_TEST_CONNECTION = By.id("selectPublisher:saveAndTestConnection");
        static final By BUTTON_SAVE = By.id("selectPublisher:save");        

        // Other publisher pages elements
        static final By LISTBOX_SELECT_PUBLISHER = By.id("listPublishers:selectPublisher");
        static final By INPUT_PUBLISHER_NAME = By.id("listPublishers:newPublisherName");
        static final By EDIT_PUBLISHER_TITLE = By.id("publisherTitle");
        static final By LINK_CANCEL_EDIT_PUBLISHER = By.id("selectPublisher:cancelEditPublisher");
        static final By SELECT_PUBLISHER_TYPE = By.id("selectPublisher:selectpublishertype");
        static final By AVAILABLE_PUBLISHERS_LABEL = By.id("selectPublisher:multigrouppublisherpage:availablepublisherslabel");
        static final By PUBLISHER_GROUPS_TEXT_AREA = By.id("selectPublisher:multigrouppublisherpage:publishergroupstextarea");
        static final By AVAILABLE_PUBLISHERS = By.id("selectPublisher:multigrouppublisherpage:availablepublishers");
        
        static final By getDataSourceInputText() {
            return By.xpath("//input[starts-with(@name,'selectPublisher:custompublisherpage:')]");
        }
    } 
    
    public PublisherHelper(WebDriver webDriver) {
        super(webDriver);
    }

    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }
    
    public void addPublisher(final String publisherName) {
        fillInput(Page.INPUT_PUBLISHER_NAME, publisherName);
        clickLink(Page.BUTTON_ADD_PUBLISHER);
    }
    
    public void clonePublisher(final String clonePublisherName) {
        fillInput(Page.INPUT_PUBLISHER_NAME, clonePublisherName);
        clickLink(Page.BUTTON_CLONE_PUBLISHER);
    }

    public void renamePublisher(final String renamePublisherName) {
        fillInput(Page.INPUT_PUBLISHER_NAME, renamePublisherName);
        clickLink(Page.BUTTON_RENAME_PUBLISHER);
    }
    
    public void setDataSource(final String dataSource) {
        fillInput(Page.getDataSourceInputText(), dataSource);
    }

    /**
     * Asserts that publisherName is listed in the list of available publishers.
     * 
     * @param publisherName
     */
    public void assertPublisherExists(final String publisherName) {
        final List<String> selectValues = getSelectValues(Page.LISTBOX_SELECT_PUBLISHER);
        assertNotNull(publisherName + " was not found in the List of Publishers", selectValues);
        assertTrue(publisherName + " was not found in the List of Publishers", selectValues.contains(publisherName));
    }
    
    /**
     * Asserts that publisherName is not listed in the available publishers list.
     * 
     * @param publisherName
     */
    public void assertPublisherDeleted(final String publisherName) {
        final List<String> selectNames = getSelectNames(Page.LISTBOX_SELECT_PUBLISHER);
        assertFalse(publisherName + " was found in the List of Publishers", selectNames.contains(publisherName));
    }
    
    public void selectPublisherFromList(final String publisherName) {
        selectOptionByValue(Page.LISTBOX_SELECT_PUBLISHER, publisherName);
    }

    public void deletePublisher(final String expectedAlertMessage, final boolean isConfirmed) {
        clickLink(Page.BUTTON_DELETE_PUBLISHER);
        assertAndConfirmAlertPopUp(expectedAlertMessage, isConfirmed);
    }
    
    public void editPublisher() {
        clickLink(Page.BUTTON_EDIT_PUBLISHER);
    }
    
    public void assertEditPublisherTitleExistsAndCorrect(final String expectedTitle) {
        assertEquals( 
                "Unexpected value for publisher page title",
                expectedTitle,
                getElementText(Page.EDIT_PUBLISHER_TITLE));
    }
    
    public void cancelEditPublisher() {
        clickLink(Page.LINK_CANCEL_EDIT_PUBLISHER);
    }

    public void assertBackToListPublisherPage() {
        assertPageUri(Page.PAGE_URI);        
    }

    public void assertPublishersExist(final Collection<String> publishers) {
        publishers.forEach(publisher -> assertPublisherExists(publisher));
    }

    /**
     * Changes the publisher type to publisherType by selecting from the drop-down list of publishers.
     * 
     * @param publisherType
     */
    public void setPublisherType(final String publisherType) {
        selectOptionByValue(Page.SELECT_PUBLISHER_TYPE, publisherType);
    }

    /**
     * Asserts that specific elements which belong to the multigroup publisher page exist and available publishers are as expected.
     * 
     * @param expectedAvailablePublishers
     */
    public void assertMultiGroupPublisherPage(final String expectedAvailablePublishers) {
        assertElementExists(Page.AVAILABLE_PUBLISHERS_LABEL, "Available publishers element not found in the page!");
        assertElementExists(Page.PUBLISHER_GROUPS_TEXT_AREA, "Publisher groups text area not found in the page!");
        assertTrue("Unexpected value for the available publishers", getElementText(Page.AVAILABLE_PUBLISHERS).contains(expectedAvailablePublishers));
    }

    public void saveAndTestConnection() {
        clickLink(Page.BUTTON_SAVE_AND_TEST_CONNECTION);
    }

    /**
     * Asserts the infoMessage appears in the page
     * @param infoMessage
     */
    public void assertHasInfoMessage(final String infoMessage) {
        assertInfoMessageAppears(infoMessage, "Connection tested successfully message element not found!", "Unexpected test and save connection message!");
    }

    /**
     * Sets the publisher groups of the multi group publisher to publisherGroup 
     * @param publisherGroup
     */
    public void setPublisherGroup(final String publisherGroup) {
        fillTextarea(Page.PUBLISHER_GROUPS_TEXT_AREA, publisherGroup, true);
    }

    public void save() {
        clickLink(Page.BUTTON_SAVE);
    }

    /**
     * Asserts the errorMessage appears in the page
     * 
     * @param errorMessage
     */
    public void assertHasErrorMessage(final String errorMessage) {
        assertErrorMessageAppears(errorMessage, "Publisher non existing message element not found!", "Unexpected save publisher message!");
    }

    /**
     * Asserts that multigroup publishers's publisher group text is set properly
     * 
     * @param existingPublishers
     */
    public void assertMultiGroupPublishersTextAreaValue(final String existingPublishers) {
        assertEquals( 
                "Unexpected value for publisher group text area",
                existingPublishers,
                getElementText(Page.PUBLISHER_GROUPS_TEXT_AREA));        
    }
}
