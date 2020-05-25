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

import java.util.List;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.ApprovalProfilesHelper;
import org.ejbca.webtest.helper.CaActivationHelper;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.RaWebHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * Web Test to verify that Accumulative Approval Profiles work as expected.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-51>ECAQA-51</a>
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa51_AccumulativeProfilesApprovalRequest extends WebTestBase{

    private static int approvalId = -1;
    
    // Helpers
    private static ApprovalProfilesHelper approvalProfilesHelper;
    private static CaActivationHelper caActivationHelper;
    private static CaHelper caHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static RaWebHelper raWebHelper;
    
    // Test Data
    public static class TestData {
        static final String APPROVAL_PROFILE_NAME = "ECAQA51_Require_1_Approval";
        static final String APPROVAL_PROFILE_TYPE_ACCUMULATIVE_APPROVAL = "Accumulative Approval";
        static final String CA_NAME = "ECAQA51_ApprovalCA";
        static final String CA_VALIDITY = "1y";
        static final String END_ENTITY_PROFILE_NAME = "ECAQA_51_TestApprovalEndEntity";
        static final String END_ENTITY_PROFILE_NAME_EMPTY = "";
        static final String RA_PENDING_APPROVAL_TYPE_ACTIVATE_CA_TOKEN = "Activate CA Token";
        static final String RA_PENDING_APPROVAL_STATUS = "Waiting for Approval";
    }
    
    @BeforeClass
    public static void init() {
    // Super
    beforeClass(true, null);
    final WebDriver webDriver = getWebDriver();
    // Helpers
    approvalProfilesHelper = new ApprovalProfilesHelper(webDriver);
    caActivationHelper = new CaActivationHelper(webDriver);
    caHelper = new CaHelper(webDriver);
    endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
    raWebHelper = new RaWebHelper(webDriver);
    }
    
    @AfterClass
    public static void exit() {
        // Remove CA
        removeCaByName(TestData.CA_NAME);
        // Remove CryptoToken
        removeCryptoTokenByCaName(TestData.CA_NAME);
        // Remove Approval Profile
        removeApprovalProfileByName(TestData.APPROVAL_PROFILE_NAME);
        // Remove Approval Request
        removeApprovalRequestByRequestId(approvalId);
        // Remove End Entity Profile
        removeEndEntityProfileByName(TestData.END_ENTITY_PROFILE_NAME);
        afterClass();
    }
    
    // Add Approval Profile
    @Test
    public void stepA_prerequisiteAddApprovalProfile() {
        approvalProfilesHelper.openPage(getAdminWebUrl());
        approvalProfilesHelper.addApprovalProfile(TestData.APPROVAL_PROFILE_NAME);
        approvalProfilesHelper.openEditApprovalProfilePage(TestData.APPROVAL_PROFILE_NAME);
        approvalProfilesHelper.setApprovalProfileType(TestData.APPROVAL_PROFILE_TYPE_ACCUMULATIVE_APPROVAL);
        approvalProfilesHelper.assertApprovalProfileTypeSelectedName("Accumulative Approval");
    }
    
    // Create CA
    @Test
    public void stepB_prerequisiteCreateCa() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }
    
    // Create EE profile
    @Test
    public void stepC_addEndEntityProfile() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.assertEndEntityProfileNameExists(TestData.END_ENTITY_PROFILE_NAME);
    }
    
    //Edit Crypto Token no Auto-activation
    @Test
    public void stepD_setCryptoTokenAutoActivationDeselect() {
        caActivationHelper.openPage(getAdminWebUrl());
        caActivationHelper.openPageCaCryptoTokenEditPage(TestData.CA_NAME);
        caActivationHelper.editCryptoTokenSetNoAutoActivation();
    }
        
    // CA Activation set No Keep-active
    @Test
    public void stepE_deActivateCaService() {
        caActivationHelper.openPage(getAdminWebUrl());
        caActivationHelper.setCaServiceStateOffline(TestData.CA_NAME);
    }
    
    // Approval Settings for CA
    @Test
    public void stepF_editCaSetApprovalProfile() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(TestData.CA_NAME, "Off-line");
        caHelper.setCaServiceActivationApprovalProfile(TestData.APPROVAL_PROFILE_NAME);
        caHelper.saveCa();    
    }
    
    // CA Service Activate
    @Test
    public void stepG_activateCaService() {
        caActivationHelper.openPage(getAdminWebUrl());
        caActivationHelper.setCaServiceStateActive(TestData.CA_NAME);
    }
    
    // CA Activation cryptotoken No Keep-active
    @Test
    public void stepH_deActivateCryptoToken() {
        caActivationHelper.openPage(getAdminWebUrl());
        caActivationHelper.setCaCryptoTokenStateOffline(TestData.CA_NAME);
    }
    
    // CA Activation cryptotoken Activate
    @Test
    public void stepI_activateCryptoToken() {
        caActivationHelper.openPage(getAdminWebUrl());
        caActivationHelper.setCaCryptoTokenStateActive(TestData.CA_NAME);
    }
    
    // Find and assert approval request
    @Test
    public void stepJ_findAssertPendingApprovals() {
        raWebHelper.openPage(getRaWebUrl());
        raWebHelper.clickMenuManageRequests();
        raWebHelper.clickTabPendingRequests();
        //Assert approval request exist
        final List<WebElement> pendingApprovalRequestRow = raWebHelper.getRequestsTableRow(TestData.CA_NAME, TestData.RA_PENDING_APPROVAL_TYPE_ACTIVATE_CA_TOKEN, TestData.END_ENTITY_PROFILE_NAME_EMPTY, TestData.RA_PENDING_APPROVAL_STATUS);
        raWebHelper.assertHasRequestRow(pendingApprovalRequestRow);
        approvalId = raWebHelper.getRequestIdFromRequestRow(pendingApprovalRequestRow);
    }
    
}
