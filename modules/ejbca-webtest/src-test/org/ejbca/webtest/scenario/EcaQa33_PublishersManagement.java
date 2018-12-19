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
        static final String PUBLISHER_NAME = "MyPublisher";
        static final String CLONE_PUBLISHER_NAME = "TestPublisher";
        static final String RENAME_PUBLISHER_NAME = "NewPublisher";

    }
    
    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        publisherHelper = new PublisherHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws ReferencesToItemExistException, AuthorizationDeniedException {
        removePublisherByName(TestData.PUBLISHER_NAME);
        removePublisherByName(TestData.CLONE_PUBLISHER_NAME);
        removePublisherByName(TestData.RENAME_PUBLISHER_NAME);
        afterClass();
    }
    
    @Test
    public void stepA_addPublisher() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.addPublisher(TestData.PUBLISHER_NAME);
        publisherHelper.assertPublisherExists(TestData.PUBLISHER_NAME);
    }
    
    @Test
    public void stepB_cloneExistingPublisher() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.PUBLISHER_NAME);
        publisherHelper.clonePublisher(TestData.CLONE_PUBLISHER_NAME);
        publisherHelper.assertPublisherExists(TestData.CLONE_PUBLISHER_NAME);
    }
    
    @Test
    public void stepC_renameExistingPublisher() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.CLONE_PUBLISHER_NAME);
        publisherHelper.renamePublisher(TestData.RENAME_PUBLISHER_NAME);
        publisherHelper.assertPublisherExists(TestData.RENAME_PUBLISHER_NAME);
    }
    
    
    
    
}
