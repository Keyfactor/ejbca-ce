/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.resource;

import java.util.LinkedHashMap;
import java.util.List;

import javax.ws.rs.core.Response;

import org.cesecore.CaTestUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.ClientResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * A unit test class for CaManagementRestResourceSystemTest to test its content.
 *
 * @version $Id: CaManagementRestResourceSystemTest.java 32360 2019-05-17 12:50:59Z tarmo_r_helmes $
 */
public class CaManagementRestResourceSystemTest extends RestResourceSystemTestBase {

    private static final JSONParser jsonParser = new JSONParser();
    
    private final String caName = "CaManagementTestCA";
    private final String cryptoTokenName = "CaManagementTestCryptoToken";
    private final String caDN = "CN=CaManagementTestCA";
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();

    }

    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        // remove CA
        CaTestUtils.removeCa(INTERNAL_ADMIN_TOKEN, cryptoTokenName, caName);
        // remove cryptotoken
        CryptoTokenTestUtils.removeCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenName);
    }
    
    @Test
    public void shouldReturnStatusInformation() throws Exception {
        // given
        final String expectedStatus = "OK";
        final String expectedVersion = "1.0";
        final String expectedRevision = GlobalConfiguration.EJBCA_VERSION;
        // when
        final ClientResponse<?> actualResponse = newRequest("/v1/ca_management/status").get();
        try {
            final String actualJsonString = actualResponse.getEntity(String.class);
    
            // then
            assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
            assertJsonContentType(actualResponse);
            assertProperJsonStatusResponse(expectedStatus, expectedVersion, expectedRevision, actualJsonString);
        } finally {
            actualResponse.close();
        }
    }

    /**
     * Disables REST and then runs a simple REST access test which will expect status 403 when
     * service is disabled by configuration.
     * @throws Exception
     */
    @Test
    public void shouldRestrictAccessToRestResourceIfProtocolDisabled() throws Exception {
        // given
        disableRestProtocolConfiguration();
        // when
        final ClientResponse<?> actualResponse = newRequest("/v1/ca_management/status").get();
        try {
            final int status = actualResponse.getStatus();
        
            // then
            assertEquals("Unexpected response after disabling protocol", 403, status);
            // restore state
            enableRestProtocolConfiguration();
        } finally {
            actualResponse.close();
        }
    }
    
    
    @Test
    public void shouldSuccessfullyActivateOfflineCa() throws Exception {
        // create crypto token
        CryptoTokenTestUtils.createSoftCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenName);
        // create CA
        CaTestUtils.createX509Ca(INTERNAL_ADMIN_TOKEN, cryptoTokenName, caName, caDN, CAConstants.CA_OFFLINE);
        
        // Perform CA activation REST call
        final ClientRequest request = newRequest("/v1/ca_management/" + caName + "/activate");
        final ClientResponse<?> actualResponse = request.put();
        try {
            final int status = actualResponse.getStatus();
            
            // Verify result
            assertEquals(HTTP_STATUS_CODE_OK, status);
        } finally {
            actualResponse.close();
        }
    }
    
    
    @Test
    public void shouldReturn200OnActivatingAlreadyActiveCa() throws Exception {
        // create crypto token
        CryptoTokenTestUtils.createSoftCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenName);
        // create CA
        CaTestUtils.createX509Ca(INTERNAL_ADMIN_TOKEN, cryptoTokenName, caName, caDN, CAConstants.CA_ACTIVE);
        
        // when
        // Perform CA activation REST call
        final ClientRequest request = newRequest("/v1/ca_management/" + caName + "/activate");
        final ClientResponse<?> actualResponse = request.put();
        try {
            final int status = actualResponse.getStatus();
            
            // then
            assertEquals(HTTP_STATUS_CODE_OK, status);
        } finally {
            actualResponse.close();
        }
    }
    
    
    @Test
    public void shouldReturn422OnActivatingExpiredCa() throws Exception {
        // create crypto token
        CryptoTokenTestUtils.createSoftCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenName);
        // create CA
        X509CA ca = CaTestUtils.createX509Ca(INTERNAL_ADMIN_TOKEN, cryptoTokenName, caName, caDN, CAConstants.CA_EXPIRED);
        
        // when
        // Perform CA activation REST call
        final ClientRequest request = newRequest("/v1/ca_management/" + caName + "/activate");
        final ClientResponse<?> actualResponse = request.put();
        try {
            final int status = actualResponse.getStatus();
            
            // then
            // Verify result
            assertEquals(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, status);
            
            final String expectedResonseMessage = "CA " + caName + " must have the status 'offline' in order to be activated";
            
            final String actualJsonString = actualResponse.getEntity(String.class);
            final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
            final String responseErrorMessage = (String) actualJsonObject.get("error_message");
            assertNotNull("error_message in the response should not have been NULL.", responseErrorMessage);
            assertTrue("The REST method failed with an invalid cause. response error_message was: " + responseErrorMessage, responseErrorMessage.contains(expectedResonseMessage));
        } finally {
            actualResponse.close();
        }
    }
    
    @Test
    public void shouldReturn202OnActivatingOfflineCaWithApprovals() throws Exception {
        // create crypto token
        CryptoTokenTestUtils.createSoftCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenName);
        // create CA
        AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile("Test Approval Profile");
        approvalProfile.setNumberOfApprovalsRequired(1);
        approvalProfile.initialize();
        int profileId = -1;
        int approvalId = -1;

        // Generate approval request
        profileId = approvalProfileSession.addApprovalProfile(INTERNAL_ADMIN_TOKEN, approvalProfile);
        LinkedHashMap<ApprovalRequestType, Integer> approvals = new LinkedHashMap<>();
        approvals.put(ApprovalRequestType.ACTIVATECA, profileId);
        
        X509CA ca = CaTestUtils.createX509CaWithApprovals(INTERNAL_ADMIN_TOKEN, cryptoTokenName, caName, caDN, CAConstants.CA_OFFLINE, approvals);
        
        // when
        // Perform CA activation REST call
        final ClientRequest request = newRequest("/v1/ca_management/" + caName + "/activate");
        final ClientResponse<?> actualResponse = request.put();
        try {
            final int status = actualResponse.getStatus();
            
            // then
            final String actualJsonString = actualResponse.getEntity(String.class);
            
            System.out.println(actualJsonString);
            
            final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
            final String responseInfoMessage = (String) actualJsonObject.get("info_message");
            System.out.println("Response: " + responseInfoMessage);
            
            assertEquals(HTTP_STATUS_CODE_ACCEPTED, status);
            assertNotNull("info_message in the response should not have been NULL.", responseInfoMessage);
            assertEquals("CA activation has been sent for approval by authorized administrators.", responseInfoMessage);
        } finally {
            actualResponse.close();
            approvalProfileSession.removeApprovalProfile(INTERNAL_ADMIN_TOKEN, profileId);
            removeApprovalDataByCaId(ca.getCAId());
        }
    }
    
    
    @Test
    public void shouldReturn200OnActivatingAlreadyActiveCaWithApprovals() throws Exception {
        // create crypto token
        CryptoTokenTestUtils.createSoftCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenName);
        // create CA
        AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile("Test Approval Profile");
        approvalProfile.setNumberOfApprovalsRequired(1);
        approvalProfile.initialize();
        int profileId = -1;
        int approvalId = -1;

        // Generate approval request
        profileId = approvalProfileSession.addApprovalProfile(INTERNAL_ADMIN_TOKEN, approvalProfile);
        LinkedHashMap<ApprovalRequestType, Integer> approvals = new LinkedHashMap<>();
        approvals.put(ApprovalRequestType.ACTIVATECA, profileId);
        
        X509CA ca = CaTestUtils.createX509CaWithApprovals(INTERNAL_ADMIN_TOKEN, cryptoTokenName, caName, caDN, CAConstants.CA_ACTIVE, approvals);
        
        // when
        // Perform CA activation REST call
        final ClientRequest request = newRequest("/v1/ca_management/" + caName + "/activate");
        final ClientResponse<?> actualResponse = request.put();
        try {
            final int status = actualResponse.getStatus();
            
            // then
            assertEquals(HTTP_STATUS_CODE_OK, status);
        } finally {
            actualResponse.close();
            approvalProfileSession.removeApprovalProfile(INTERNAL_ADMIN_TOKEN, profileId);
            removeApprovalDataByCaId(ca.getCAId());
        }
    }
    
    private void removeApprovalDataByCaId(int caId) {
        final org.ejbca.util.query.Query query = new org.ejbca.util.query.Query(org.ejbca.util.query.Query.TYPE_APPROVALQUERY);
        query.add(ApprovalMatch.MATCH_WITH_CAID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(caId));
        final List<ApprovalDataVO> approvals;
        try {
            approvals = approvalProxySession.query(query, 0, 100, "", "");
        } catch (IllegalQueryException e) {
            throw new IllegalStateException("Query for approval request failed: " + e.getMessage(), e);
        }
        for (ApprovalDataVO approval : approvals) {
            approvalSession.removeApprovalRequest(INTERNAL_ADMIN_TOKEN, approval.getId());            
            System.out.println("Removed approval with ID=" + approval.getApprovalId());
        }
    }
    
    @Test
    public void shouldReturn400OnActivatingNonExistingCa() throws Exception {
        
        final ClientRequest request = newRequest("/v1/ca_management/" + "UnknownCA" + "/activate");
        
        // when
        // Perform CA activation REST call
        final ClientResponse<?> actualResponse = request.put();
        try {
         // then
            final int status = actualResponse.getStatus();
            assertEquals(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, status);
            
            final String expectedResonseMessage = "Unknown CA name";
            
            final String actualJsonString = actualResponse.getEntity(String.class);
            final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
            final String responseErrorMessage = (String) actualJsonObject.get("error_message");
            assertNotNull("error_message in the response should not have been NULL.", responseErrorMessage);
            assertEquals("The REST method failed with an invalid cause. Response error_message was: " + responseErrorMessage, expectedResonseMessage, responseErrorMessage);
        } finally {
            actualResponse.close();
        }
    }
    
    @Test
    public void shouldSuccessfullyDeactivateActiveCa() throws Exception {
        // create crypto token
        CryptoTokenTestUtils.createSoftCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenName);
        // create CA
        CaTestUtils.createActiveX509Ca(INTERNAL_ADMIN_TOKEN, cryptoTokenName, caName, caDN);
        
        // Perform CA activation REST call
        final ClientRequest request = newRequest("/v1/ca_management/" + caName + "/deactivate");
        final ClientResponse<?> actualResponse = request.put();
        try {
            final int status = actualResponse.getStatus();
            
            // Verify result
            assertEquals(HTTP_STATUS_CODE_OK, status);
        } finally {
            actualResponse.close();
        }
    }
    
    @Test
    public void shouldReturn200OnDeactivatingAlreadyDeactiveCa() throws Exception {
        // create crypto token
        CryptoTokenTestUtils.createSoftCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenName);
        // create CA
        CaTestUtils.createX509Ca(INTERNAL_ADMIN_TOKEN, cryptoTokenName, caName, caDN, CAConstants.CA_OFFLINE);
        
        // when
        // Perform CA deactivation REST call
        final ClientRequest request = newRequest("/v1/ca_management/" + caName + "/deactivate");
        final ClientResponse<?> actualResponse = request.put();
        try {
            final int status = actualResponse.getStatus();
            
            // then
            assertEquals(HTTP_STATUS_CODE_OK, status);
        } finally {
            actualResponse.close();
        }
    }
    
    
    @Test
    public void shouldReturn422OnDeactivatingExpiredCa() throws Exception {
        // create crypto token
        CryptoTokenTestUtils.createSoftCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenName);
        // create CA
        X509CA ca = CaTestUtils.createX509Ca(INTERNAL_ADMIN_TOKEN, cryptoTokenName, caName, caDN, CAConstants.CA_EXPIRED);
        
        // when
        // Perform CA deactivation REST call
        final ClientRequest request = newRequest("/v1/ca_management/" + caName + "/deactivate");
        final ClientResponse<?> actualResponse = request.put();
        try {
            final int status = actualResponse.getStatus();
            
            // then
            assertEquals(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, status);
            
            final String expectedResonseMessage = "CA " + caName + " must have the status 'active' in order to be deactivated";
            
            final String actualJsonString = actualResponse.getEntity(String.class);
            final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
            final String responseErrorMessage = (String) actualJsonObject.get("error_message");
            assertNotNull("error_message in the response should not have been NULL.", responseErrorMessage);
            assertTrue("The REST method failed with an invalid cause. Response error_message was: " + responseErrorMessage, responseErrorMessage.contains(expectedResonseMessage));
        } finally {
            actualResponse.close();
        }
    }
    
    @Test
    public void shouldReturn422OnDeactivatingNonExistingCa() throws Exception {
        
        final ClientRequest request = newRequest("/v1/ca_management/" + "UnknownCA" + "/deactivate");
        
        // when
        // Perform CA deactivation REST call
        final ClientResponse<?> actualResponse = request.put();
        try {
            // then
            final int status = actualResponse.getStatus();
            assertEquals(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, status);
            
            final String expectedResonseMessage = "Unknown CA name";
            
            final String actualJsonString = actualResponse.getEntity(String.class);
            final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
            final String responseErrorMessage = (String) actualJsonObject.get("error_message");
            assertNotNull("error_message in the response should not have been NULL.", responseErrorMessage);
            assertEquals("The REST method failed with an invalid cause. Response error_message was: " + responseErrorMessage, expectedResonseMessage, responseErrorMessage);
        } finally {
            actualResponse.close();
        }
    }
}
