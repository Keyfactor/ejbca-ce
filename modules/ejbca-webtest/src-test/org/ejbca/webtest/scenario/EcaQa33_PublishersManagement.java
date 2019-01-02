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
package org.ejbca.webtest.scenario;

import java.util.HashMap;
import java.util.Map;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.common.exception.ReferencesToItemExistException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.PublisherHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * 
 * @version $Id$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa33_PublishersManagement extends WebTestBase {

    private static WebDriver webDriver;
    
    // Helpers
    private static PublisherHelper publisherHelper; 
    
    // Test Data
    private static class TestData {
        static final Map<String, String> PUBLISHERS;
        static {
            PUBLISHERS = new HashMap<>();
            PUBLISHERS.put("PUBLISHER_NAME", "MyPublisher");
            PUBLISHERS.put("CLONE_PUBLISHER_NAME", "TestPublisher");
            PUBLISHERS.put("RENAME_PUBLISHER_NAME", "NewPublisher");
        }
        static final String PUBLISHER_DELETE_MESSAGE = "Are you sure you want to delete this?";
    }
    
    @BeforeClass
    public static void init() throws ReferencesToItemExistException, AuthorizationDeniedException {
        beforeClass(true, null);
        webDriver = getWebDriver();
        publisherHelper = new PublisherHelper(webDriver);
        removeExistingPublishers();
    }

    @AfterClass
    public static void exit() throws ReferencesToItemExistException, AuthorizationDeniedException {
        removeExistingPublishers();
        afterClass();
    }
    
    @Test
    public void stepA_addPublisher() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.addPublisher(TestData.PUBLISHERS.get("PUBLISHER_NAME"));
        publisherHelper.assertPublisherExists(TestData.PUBLISHERS.get("PUBLISHER_NAME"));
    }
    
    @Test
    public void stepB_cloneExistingPublisher() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.PUBLISHERS.get("PUBLISHER_NAME"));
        publisherHelper.clonePublisher(TestData.PUBLISHERS.get("CLONE_PUBLISHER_NAME"));
        publisherHelper.assertPublisherExists(TestData.PUBLISHERS.get("CLONE_PUBLISHER_NAME"));
    }
    
    @Test
    public void stepC_renameExistingPublisher() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.PUBLISHERS.get("CLONE_PUBLISHER_NAME"));
        publisherHelper.renamePublisher(TestData.PUBLISHERS.get("RENAME_PUBLISHER_NAME"));
        publisherHelper.assertPublisherExists(TestData.PUBLISHERS.get("RENAME_PUBLISHER_NAME"));
    }
    
    @Test
    public void stepD_deleteExistingPublisher() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.PUBLISHERS.get("RENAME_PUBLISHER_NAME"));
        publisherHelper.deletePublisher(TestData.PUBLISHER_DELETE_MESSAGE, true);
        publisherHelper.openPage(getAdminWebUrl()); // Reload the page to get the changes in the publisher list
        publisherHelper.assertPublisherDeleted(TestData.PUBLISHERS.get("RENAME_PUBLISHER_NAME"));
    }
    
    @Test
    public void stepE_editPublisher() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.PUBLISHERS.get("PUBLISHER_NAME"));
        publisherHelper.editPublisher();
        publisherHelper.assertEditPublisherTitleExistsAndCorrect("Publisher : " + TestData.PUBLISHERS.get("PUBLISHER_NAME"));
        publisherHelper.cancelEditPublisher();
        publisherHelper.assertBackToListPublisherPage();
    }
}
