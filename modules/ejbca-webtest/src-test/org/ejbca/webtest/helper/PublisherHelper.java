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
        static final By INPUT_PUBLISHER_NAME = By.id("listPublishers:newPublisherName");
        static final By BUTTON_ADD_PUBLISHER = By.id("listPublishers:addButton");
        static final By BUTTON_CLONE_PUBLISHER = By.id("listPublishers:cloneButton");
        static final By BUTTON_RENAME_PUBLISHER = By.id("listPublishers:renameButton");
        static final By SELECT_PUBLISHER = By.id("listPublishers:selectPublisher");
        static final By DELETE_PUBLISHER = By.id("listPublishers:deleteButton");
        static final By EDIT_PUBLISHER = By.id("listPublishers:editButton");
        static final By EDIT_PUBLISHER_TITLE = By.id("publisherTitle");
        static final By CANCEL_EDIT_PUBLISHER = By.id("selectPublisher:cancelEditPublisher");
        static final By SELECT_PUBLISHER_TYPE = By.id("selectPublisher:selectpublishertype");
        static final By AVAILABLE_PUBLISHERS_LABEL = By.id("selectPublisher:multigrouppublisherpage:availablepublisherslabel");
        static final By PUBLISHER_GROUPS_TEXT_AREA = By.id("selectPublisher:multigrouppublisherpage:publishergroupstextarea");
        static final By AVAILABLE_PUBLISHERS = By.id("selectPublisher:multigrouppublisherpage:availablepublishers");
        static final By BUTTON_SAVE_AND_TEST_CONNECTION = By.id("selectPublisher:saveAndTestConnection");
        static final By BUTTON_SAVE = By.id("selectPublisher:save");

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

    public void assertPublisherExists(final String publisherName) {
        final List<String> selectNames = getSelectNames(Page.SELECT_PUBLISHER);
        assertNotNull(publisherName + " was not found in the List of Publishers", selectNames);
        assertTrue(publisherName + " was not found in the List of Publishers", selectNames.contains(publisherName));
    }
    
    public void assertPublisherDeleted(final String publisherName) {
        final List<String> selectNames = getSelectNames(Page.SELECT_PUBLISHER);
        assertFalse(publisherName + " was found in the List of Publishers", selectNames.contains(publisherName));
    }
    
    public void selectPublisherFromList(final String publisherName) {
        selectOptionByName(Page.SELECT_PUBLISHER, publisherName);
    }

    public void deletePublisher(final String expectedAlertMessage, final boolean isConfirmed) {
        clickLink(Page.DELETE_PUBLISHER);
        assertAndConfirmAlertPopUp(expectedAlertMessage, isConfirmed);
    }
    
    public void editPublisher() {
        clickLink(Page.EDIT_PUBLISHER);
    }
    
    public void assertEditPublisherTitleExistsAndCorrect(final String expectedTitle) {
        assertEquals( 
                "Unexpected value for publisher page title",
                expectedTitle,
                getElementText(Page.EDIT_PUBLISHER_TITLE));
    }
    
    public void cancelEditPublisher() {
        clickLink(Page.CANCEL_EDIT_PUBLISHER);
    }

    public void assertBackToListPublisherPage() {
        assertPageUri(Page.PAGE_URI);        
    }

    public void assertPublishersExist(final Collection<String> publishers) {
        publishers.forEach(publisher -> assertPublisherExists(publisher));
    }

    public void setPublisherType(final String publisherType) {
        selectOptionByValue(Page.SELECT_PUBLISHER_TYPE, publisherType);
    }

    public void assertMultiGroupPublisherPage(final String expectedAvailablePublishers) {
        assertElementExists(Page.AVAILABLE_PUBLISHERS_LABEL, "Available publishers element not found in the page!");
        assertElementExists(Page.PUBLISHER_GROUPS_TEXT_AREA, "Publisher groups text area not found in the page!");
        assertEquals("Unexpected value for the available publishers", expectedAvailablePublishers, getElementText(Page.AVAILABLE_PUBLISHERS));
    }

    public void saveAndTestConnection() {
        clickLink(Page.BUTTON_SAVE_AND_TEST_CONNECTION);
    }

    public void assertHasInfoMessage(final String infoMessage) {
        assertInfoMessageAppears(infoMessage, "Connection tested successfully message element not found!", "Unexpected test and save connection message!");
    }

    public void setPublisherGroup(final String nonexistingPublisher) {
        fillTextarea(Page.PUBLISHER_GROUPS_TEXT_AREA, nonexistingPublisher, true);
    }

    public void save() {
        clickLink(Page.BUTTON_SAVE);
    }

    public void assertHasErrorMessage(final String errorMessage) {
        assertErrorMessageAppears(errorMessage, "Publisher non existing message element not found!", "Unexpected save publisher message!");
    }

    public void assertMultiGroupPublishersTextAreaValue(final String existingPublishers) {
        assertEquals( 
                "Unexpected value for publisher group text area",
                existingPublishers,
                getElementText(Page.PUBLISHER_GROUPS_TEXT_AREA));        
    }
}
