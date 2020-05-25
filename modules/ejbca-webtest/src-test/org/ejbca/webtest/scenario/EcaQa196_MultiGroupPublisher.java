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

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.cesecore.common.exception.ReferencesToItemExistException;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.PublisherHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * For some unclear reason this test does not run stable enough in the Firefox graphical mode 
 * (specially if you have already existing publishers configured in EJBCA).
 * The reason is not obvious but it could be related to the screen resolution issue of Firefox when used by Selenium in GUI mode.
 * Due to this issue and in order to get the stable results you should run this in Firefox headless mode 
 * which could be set in the browser.properties file that is located under /modules/ejbca-webtest/conf/
 * Just set the browser.headless attribute to true (default is false).
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-196">ECAQA-196</a>
 *  
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa196_MultiGroupPublisher extends WebTestBase {

    // Helpers
    private static PublisherHelper publisherHelper; 
    
    // Test Data
    private static class TestData {
        static final Map<String, String> PUBLISHERS_SIMPLE_NAME;
        static {
            PUBLISHERS_SIMPLE_NAME = new LinkedHashMap<>();
            PUBLISHERS_SIMPLE_NAME.put("PUBLISHER_ONE", "pub1");
            PUBLISHERS_SIMPLE_NAME.put("PUBLISHER_TWO", "pub2");
            PUBLISHERS_SIMPLE_NAME.put("PUBLISHER_THREE", "pub3");
            PUBLISHERS_SIMPLE_NAME.put("PUBLISHER_FOUR", "pub4");
        }
        
        static final String EXPECTED_AVAILABLE_PUBLISHERS_PUB_ONE = "pub2\npub3\npub4";
        static final String EXPECTED_AVAILABLE_PUBLISHERS_PUB_TWO = "pub3\npub4";
        static final String EXPECTED_AVAILABLE_PUBLISHERS_PUB_THREE = "pub4";
        static final String SAVE_AND_TEST_CONNECTION_SUCCESS_MESSAGE = "Connection Tested Successfully";
        static final String NONEXISTING_PUBLISHER = "blabla";
        static final String SAVE_PUBLISHER_NONEXISTING_MESSAGE = "Could not find publisher: \"blabla\"";
        static final String PUBLISHERS_GROUP_FOR_PUB_ONE = "pub2\npub3";
        static final String PUBLISHERS_GROUP_FOR_PUB_TWO = "pub3";
        static final String SAVE_AND_TEST_CONNECTION_FAIL_MESSAGE = "Following error occurred when testing connection pub2: "
                                                                    + "Publishers [pub3] failed. First failure: LDAP ERROR: "
                                                                    + "Error binding to LDAP server. Connect Error";
        static final String PUBLISHER_DELETE_MESSAGE = "Are you sure you want to delete this?";
        static final String DELETE_PUBLISHER_INUSE_ERROR_MESSAGE = "Couldn't delete publisher, references to it exist.";
    }
    
    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        publisherHelper = new PublisherHelper(getWebDriver());
    }
    
    @AfterClass
    public static void exit() throws ReferencesToItemExistException {
        for (final String publisherName : TestData.PUBLISHERS_SIMPLE_NAME.values()) {
            removePublisherByName(publisherName);
        }
        afterClass();
    }
    
    @Test
    public void stepA_addPublishers() {
        publisherHelper.openPage(getAdminWebUrl());
        for (final String publisher : TestData.PUBLISHERS_SIMPLE_NAME.values()) {
            publisherHelper.addPublisher(publisher);
        }
        publisherHelper.assertPublishersExist(TestData.PUBLISHERS_SIMPLE_NAME.values());
    }
    
    @Test
    public void stepB_setPublisherTypeAsMultiGroupPublisher() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.PUBLISHERS_SIMPLE_NAME.get("PUBLISHER_ONE"));
        publisherHelper.editPublisher();
        publisherHelper.setPublisherType(String.valueOf(PublisherConst.TYPE_MULTIGROUPPUBLISHER));
        publisherHelper.assertMultiGroupPublisherPage(TestData.EXPECTED_AVAILABLE_PUBLISHERS_PUB_ONE);
        publisherHelper.saveAndTestConnection();
        publisherHelper.assertHasInfoMessage(TestData.SAVE_AND_TEST_CONNECTION_SUCCESS_MESSAGE);
    }
    
    @Test
    public void stepC_failWhenUnknowPublisherAddedToGroup() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.PUBLISHERS_SIMPLE_NAME.get("PUBLISHER_ONE"));
        publisherHelper.editPublisher();
        publisherHelper.setPublisherGroup(TestData.NONEXISTING_PUBLISHER);
        publisherHelper.save();
        publisherHelper.assertHasErrorMessage(TestData.SAVE_PUBLISHER_NONEXISTING_MESSAGE);
    }
    
    @Test
    public void stepD_successWhenAddingTwoKnownPublishersToGroup() {
        publisherHelper.setPublisherGroup(TestData.PUBLISHERS_GROUP_FOR_PUB_ONE);
        publisherHelper.save();
        publisherHelper.assertBackToListPublisherPage();
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.PUBLISHERS_SIMPLE_NAME.get("PUBLISHER_ONE"));
        publisherHelper.editPublisher();
        publisherHelper.assertMultiGroupPublisherPage(TestData.EXPECTED_AVAILABLE_PUBLISHERS_PUB_ONE);
        publisherHelper.assertMultiGroupPublishersTextAreaValue(TestData.PUBLISHERS_GROUP_FOR_PUB_ONE);
        publisherHelper.cancelEditPublisher();
        publisherHelper.assertBackToListPublisherPage();
    }
    
    @Test
    public void stepE_addSecondMultiGroupPublisher() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.PUBLISHERS_SIMPLE_NAME.get("PUBLISHER_TWO"));
        publisherHelper.editPublisher();
        publisherHelper.setPublisherType(String.valueOf(PublisherConst.TYPE_MULTIGROUPPUBLISHER));
        publisherHelper.assertMultiGroupPublisherPage(TestData.EXPECTED_AVAILABLE_PUBLISHERS_PUB_TWO);
        publisherHelper.assertMultiGroupPublishersTextAreaValue(StringUtils.EMPTY);
        publisherHelper.setPublisherGroup(TestData.PUBLISHERS_GROUP_FOR_PUB_TWO);
        publisherHelper.saveAndTestConnection();
        publisherHelper.assertHasErrorMessage(TestData.SAVE_AND_TEST_CONNECTION_FAIL_MESSAGE);
        publisherHelper.save();
        publisherHelper.assertBackToListPublisherPage();
    }
    
    @Test
    public void stepF_addThirdMultiGroupPublisher() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.PUBLISHERS_SIMPLE_NAME.get("PUBLISHER_THREE"));
        publisherHelper.editPublisher();
        publisherHelper.setPublisherType(String.valueOf(PublisherConst.TYPE_MULTIGROUPPUBLISHER));
        publisherHelper.assertMultiGroupPublisherPage(TestData.EXPECTED_AVAILABLE_PUBLISHERS_PUB_THREE);
        publisherHelper.cancelEditPublisher();
        publisherHelper.assertBackToListPublisherPage();
    }
    
    @Test
    public void stepG_deletePublisherUsedbyAnotherPublisher() {
        publisherHelper.openPage(getAdminWebUrl());
        publisherHelper.selectPublisherFromList(TestData.PUBLISHERS_SIMPLE_NAME.get("PUBLISHER_TWO"));
        publisherHelper.deletePublisher(TestData.PUBLISHER_DELETE_MESSAGE, true);
        publisherHelper.assertHasErrorMessage(TestData.DELETE_PUBLISHER_INUSE_ERROR_MESSAGE);
    }
}
