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

import java.util.List;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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
    
    public void selectPublisherFromList(final String publisherName) {
        selectOptionByName(Page.SELECT_PUBLISHER, publisherName);
    }
}
