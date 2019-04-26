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

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CaHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * Selenium test that tests incorrect configurations related to crl partitioons in CA
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa206_CRLPartitionsIncorrectSettings extends WebTestBase {

    // Helpers
    private static CaHelper caHelper;

    // Test Data
    private static class TestData {
        static final String CA_NAME = "ECAQA-206-TestCA";
        static final String CRL_DISTRIBUTION_POINT_URL = "http://example.com/*.crl";
        static final String MISSING_ASTERISK_URL = "http://example.com/MissingAsterisk.crl";
        static final String ERROR_MESSAGE = "Partitioned CRLs are not allowed without 'Issuing Distribution Point' and 'Default CRL Distribution Point'.";
        static final String ASTERISK_MISSING_ERROR_MESSAGE = "'Default CRL Distribution Point' should contain asterisk (*) with Partitioned CRLs .";
        static final String INCORRECT_PARTITION_NUMBER_ERROR_MESSAGE = "Error: Number of CRL partitions must be higher than number of suspended CRL partitions";
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        WebDriver webDriver = getWebDriver();
        // Init helpers
        caHelper = new CaHelper(webDriver);
    }
    @AfterClass
    public static void exit(){
        // super
        afterClass();
    }

    @Test
    public void addCaWithMissingIssuingDistributionPointOnCRLs() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity("1y");
        caHelper.checkUseCrlPartitions(true);
        caHelper.setNumberOfPartitions("1");
        caHelper.setDefaultCrlDistributionPoint(TestData.CRL_DISTRIBUTION_POINT_URL);
        caHelper.createCa();
        caHelper.assertHasErrorMessage(TestData.ERROR_MESSAGE);
    }

    @Test
    public void addCaWithMissingDefaultCRLDistributionPoint() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity("1y");
        caHelper.checkUseCrlPartitions(true);
        caHelper.checkIssuingDistPointOnCrls(true);
        caHelper.setNumberOfPartitions("1");
        caHelper.createCa();
        caHelper.assertHasErrorMessage(TestData.ERROR_MESSAGE);
    }

    @Test
    public void addCaWithMissingAsteriskInUrl() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity("1y");
        caHelper.checkUseCrlPartitions(true);
        caHelper.checkIssuingDistPointOnCrls(true);
        caHelper.setNumberOfPartitions("1");
        caHelper.setDefaultCrlDistributionPoint(TestData.MISSING_ASTERISK_URL);
        caHelper.createCa();
        caHelper.assertHasErrorMessage(TestData.ASTERISK_MISSING_ERROR_MESSAGE);
    }


    @Test
    public void stepD_addCaWithIncorrectNumberOfPartitions() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity("1y");
        caHelper.checkUseCrlPartitions(true);
        caHelper.checkIssuingDistPointOnCrls(true);
        caHelper.setNumberOfPartitions("0");
        caHelper.setDefaultCrlDistributionPoint(TestData.CRL_DISTRIBUTION_POINT_URL);
        caHelper.createCa();
        caHelper.assertHasErrorMessage(TestData.INCORRECT_PARTITION_NUMBER_ERROR_MESSAGE);
    }

    @Test
    public void stepD_addCaWithSuspendedEqualToNumberOfPartitions() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity("1y");
        caHelper.checkUseCrlPartitions(true);
        caHelper.checkIssuingDistPointOnCrls(true);
        caHelper.setNumberOfPartitions("1");
        caHelper.setNumberOfSuspendedPartitions("1");
        caHelper.setDefaultCrlDistributionPoint(TestData.CRL_DISTRIBUTION_POINT_URL);
        caHelper.createCa();
        caHelper.assertHasErrorMessage(TestData.INCORRECT_PARTITION_NUMBER_ERROR_MESSAGE);
    }

    @Test
    public void stepD_addCaWithSuspendedGreaterToNumberOfPartitions() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity("1y");
        caHelper.checkUseCrlPartitions(true);
        caHelper.checkIssuingDistPointOnCrls(true);
        caHelper.setNumberOfPartitions("1");
        caHelper.setNumberOfSuspendedPartitions("2");
        caHelper.setDefaultCrlDistributionPoint(TestData.CRL_DISTRIBUTION_POINT_URL);
        caHelper.createCa();
        caHelper.assertHasErrorMessage(TestData.INCORRECT_PARTITION_NUMBER_ERROR_MESSAGE);
    }
}
