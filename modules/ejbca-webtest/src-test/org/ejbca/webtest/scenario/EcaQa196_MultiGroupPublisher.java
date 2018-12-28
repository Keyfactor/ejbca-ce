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
import org.ejbca.core.model.ca.publisher.PublisherConst;
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
public class EcaQa196_MultiGroupPublisher extends WebTestBase {

    private static WebDriver webDriver;

    // Helpers
    private static PublisherHelper publisherHelper; 
    
    // Test Data
    private static class TestData {
        static final Map<String, String> PUBLISHERS;
        static {
            PUBLISHERS = new HashMap<>();
            PUBLISHERS.put("PUBLISHER_ONE", "pub1");
            PUBLISHERS.put("PUBLISHER_TWO", "pub2");
            PUBLISHERS.put("PUBLISHER_THREE", "pub3");
            PUBLISHERS.put("PUBLISHER_FOUR", "pub4");
        }
        static final String EXPECTED_AVAILABLE_PUBLISHERS = "pub2\npub3\npub4";
        static final String SAVE_AND_TEST_CONNECTION_SUCCESS_MESSAGE = "Connection Tested Successfully";
        static final String NONEXISTING_PUBLISHER = "blabla";
        static final String SAVE_PUBLISHER_NONEXISTING_MESSAGE = "Could not find publisher: \\\"blabla\\\"";
    }
    
    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        publisherHelper = new PublisherHelper(webDriver);
    }
    
    @AfterClass
    public static void exit() throws ReferencesToItemExistException, AuthorizationDeniedException {
        for (final String publisherName : TestData.PUBLISHERS.values()) {
            removePublisherByName(publisherName);
        }
        afterClass();
    }
    
    @Test
    public void stepA_addPublishers() {
        publisherHelper.openPage(getAdminWebUrl());
        for (final String publisher : TestData.PUBLISHERS.values()) {
            publisherHelper.addPublisher(publisher);
        }
        publisherHelper.assertPublishersExist(TestData.PUBLISHERS.values());
    }
    
    @Test
    public void stepB_setPublisherTypeAsMultiGroupPublisher() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.PUBLISHERS.get("PUBLISHER_ONE"));
        publisherHelper.editPublisher();
        publisherHelper.setPublisherType(String.valueOf(PublisherConst.TYPE_MULTIGROUPPUBLISHER));
        publisherHelper.assertMultiGroupPublisherPage(TestData.EXPECTED_AVAILABLE_PUBLISHERS);
        publisherHelper.saveAndTestConnection();
        publisherHelper.assertHasInfoMessage(TestData.SAVE_AND_TEST_CONNECTION_SUCCESS_MESSAGE);
    }
    
    @Test
    public void stepC_failWhenUnknowPublisherAddedToGroup() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.PUBLISHERS.get("PUBLISHER_ONE"));
        publisherHelper.editPublisher();
        publisherHelper.setPublisherGroup(TestData.NONEXISTING_PUBLISHER);
        publisherHelper.save();
        publisherHelper.assertHasErrorMessage(TestData.SAVE_PUBLISHER_NONEXISTING_MESSAGE);
    }
}
