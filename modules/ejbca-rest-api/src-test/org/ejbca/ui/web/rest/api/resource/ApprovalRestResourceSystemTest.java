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

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.junit.util.TraceLogMethodsTestWatcher;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.easymock.EasyMock;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequestStatus;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaApprovalResponseRequest;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.TestRaMasterApiProxySessionRemote;
import org.ejbca.ui.web.rest.api.InMemoryRestServer;
import org.ejbca.ui.web.rest.api.io.request.SearchApprovalRestRequest;
import org.ejbca.ui.web.rest.api.resource.swagger.ApprovalRestResourceSwagger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.AfterClass;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestWatcher;
import org.junit.runner.RunWith;

import java.util.Map;

import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(EasyMockRunner.class)
public class ApprovalRestResourceSystemTest extends RestResourceSystemTestBase {

    private static final Logger log = Logger.getLogger(ApprovalRestResourceSystemTest.class);
    private static final JSONParser jsonParser = new JSONParser();
    private static final ApprovalSessionRemote approvalSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
    private static final ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ApprovalRestResourceSystemTest"));

    private String eeName;
    private Integer addEndEntityApprovalRequestId;
    private static Integer caId;
    private static Integer accumulativeApprovalProfileId;

    private static final String CA_NAME = "ApprovalRestResourceSystemTest_CA";
    private static final String APPROVAL_PROFILE_NAME = "ApprovalRestResourceSystemTest_APPROVAL_PROFILE";

    @Mock
    private RaMasterApiProxyBeanLocal raMasterApiSessionMock;

    private static final TestRaMasterApiProxySessionRemote raMasterApiSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(TestRaMasterApiProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static class ApprovalRestResourceWithoutSecurity extends ApprovalRestResourceSwagger {
        @Override
        protected AuthenticationToken getAdmin(HttpServletRequest requestContext, boolean allowNonAdmins) {
            return new UsernameBasedAuthenticationToken(new UsernamePrincipal("TestUser"));
        }
    }

    @TestSubject
    private final ApprovalRestResourceWithoutSecurity mockRestResource = new ApprovalRestResourceWithoutSecurity();
    private InMemoryRestServer mockRestServer;

    @Rule
    public final TestWatcher traceLogMethodsRule = new TraceLogMethodsTestWatcher(log);

    @BeforeClass
    public static void beforeClass() throws Exception {
        // Create test CA
        RestResourceSystemTestBase.beforeClass();
        X509CA testCa = CaTestUtils.createTestX509CA("CN=" + CA_NAME, "foo123".toCharArray(), false);
        caSession.addCA(alwaysAllowToken, testCa);
        CAInfo testCaInfo = testCa.getCAInfo();
        caId = testCaInfo.getCAId();
        // Create Approval Profile
        final AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile(APPROVAL_PROFILE_NAME);
        approvalProfile.setNumberOfApprovalsRequired(1);
        accumulativeApprovalProfileId = approvalProfileSession.addApprovalProfile(alwaysAllowToken, approvalProfile);
        // Apply Approval Profile to CA
        Map<ApprovalRequestType, Integer> approvalSettings = testCaInfo.getApprovals();
        approvalSettings.put(ApprovalRequestType.ADDEDITENDENTITY, accumulativeApprovalProfileId);
        testCaInfo.setApprovals(approvalSettings);
        caSession.editCA(alwaysAllowToken, testCaInfo);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
        CaTestUtils.removeCa(alwaysAllowToken, "CN=" + CA_NAME, CA_NAME);
        approvalProfileSession.removeApprovalProfile(alwaysAllowToken, accumulativeApprovalProfileId);
    }

    @Before
    public void before() throws Exception {
        mockRestServer = InMemoryRestServer.create(mockRestResource);
        mockRestServer.start();
        // Trigger an add end entity approval
        eeName = this.getClass().getName() + "_ee_" + System.currentTimeMillis();
        EndEntityInformation userdata = new EndEntityInformation(eeName, "CN=" +eeName, caId, null, null, new EndEntityType(
                EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityConstants.TOKEN_SOFT_P12, null);
        userdata.setPassword("foo123");
        try {
            endEntityManagementSession.addUser(alwaysAllowToken, userdata, true);
        } catch (WaitingForApprovalException e) {
            // Capture the requestId
            addEndEntityApprovalRequestId = e.getRequestId();
        } catch (Exception e) {
            throw new RuntimeException("Test setup failed. Could not add end entity", e);
        }
    }

    @After
    public void after() throws Exception {
        // Remove approval requests
        approvalSession.removeApprovalRequest(alwaysAllowToken, addEndEntityApprovalRequestId);
	    // Kill REST Server
        if (mockRestServer != null) {
            mockRestServer.close();
        }
    }

    @Test
    public void shouldReturnStatusInformation() throws Exception {
        // Given
        final String expectedStatus = "OK";
        final String expectedVersion = "1.0";
        final String expectedRevision = GlobalConfiguration.EJBCA_VERSION;
        // When
        final Response actualResponse = newRequest("/v1/approval/status").request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        // Then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertProperJsonStatusResponse(expectedStatus, expectedVersion, expectedRevision, actualJsonString);
    }

    @Test
    public void shouldReturnResultsForSearchApprovals() throws Exception {

        SearchApprovalRestRequest searchApprovalRestRequest = SearchApprovalRestRequest.builder()
                .searchingExpired(true)
                .searchingPending(true)
                .searchingWaitingForMe(true)
                .searchingHistorical(true)
                .build();

        // Construct POST  request
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(searchApprovalRestRequest);
        final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);

        // Send request
        final Response actualResponse = newRequest("/v1/approval/search").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        // Verify response
        assertJsonContentType(actualResponse);
        final JSONArray actualJsonArray = (JSONArray) jsonParser.parse(actualJsonString);
        assertEquals(1, actualJsonArray.size());
        final JSONObject actualJsonObject = (JSONObject) actualJsonArray.get(0);
        final Long approvalRequestId = (Long) actualJsonObject.get("request_id");
        assertNotNull(approvalRequestId);
        assertEquals(addEndEntityApprovalRequestId.intValue(), approvalRequestId.intValue());
        final String approvalRequestType = (String) actualJsonObject.get("request_type");
        assertNotNull(approvalRequestType);
        assertEquals("Add End Entity", approvalRequestType);
        final String approvalRequestDate = (String) actualJsonObject.get("request_date");
        assertNotNull(approvalRequestDate);
        final String approvalRequestExpirationDate = (String) actualJsonObject.get("expiration_date");
        assertNotNull(approvalRequestExpirationDate);
        final String approvalRequestedBy = (String) actualJsonObject.get("requested_by");
        assertNotNull(approvalRequestedBy);
        assertEquals("ApprovalRestResourceSystemTest", approvalRequestedBy);
        final Boolean approvalRequestCanBeApprovedByMe = (Boolean) actualJsonObject.get("can_be_approved_by_me");
        assertNotNull(approvalRequestCanBeApprovedByMe);


        // Now trigger a new end entity approval request
        final String endEntityName = this.getClass().getName() + "_ee_" + System.currentTimeMillis();
        EndEntityInformation userdata = new EndEntityInformation(endEntityName, "CN=" +endEntityName, caId, null, null, new EndEntityType(
                EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityConstants.TOKEN_SOFT_P12, null);
        userdata.setPassword("foo123");
        int newApprovalRequestId = 0;
        try {
            endEntityManagementSession.addUser(alwaysAllowToken, userdata, true);
        } catch (WaitingForApprovalException e) {
            // Capture the requestId
            newApprovalRequestId = e.getRequestId();

            final Response actualResponseUpdated = newRequest("/v1/approval/search").request().post(requestEntity);

            final String actualJsonStringUpdated = actualResponseUpdated.readEntity(String.class);
            // Verify response
            assertJsonContentType(actualResponseUpdated);
            final JSONArray actualJsonArrayUpdated = (JSONArray) jsonParser.parse(actualJsonStringUpdated);
            assertEquals(2, actualJsonArrayUpdated.size());

            final JSONObject actualJsonObjectUpdated = (JSONObject) actualJsonArrayUpdated.get(1);
            assertNotNull(actualJsonObjectUpdated.get("request_id"));

            final String approvalRequestTypeUpdated = (String) actualJsonObjectUpdated.get("request_type");
            assertNotNull(approvalRequestTypeUpdated);
            assertEquals("Add End Entity", approvalRequestTypeUpdated);

            final String approvalRequestDateUpdated = (String) actualJsonObjectUpdated.get("request_date");
            assertNotNull(approvalRequestDateUpdated);
            final String approvalRequestExpirationDateUpdated = (String) actualJsonObjectUpdated.get("expiration_date");
            assertNotNull(approvalRequestExpirationDateUpdated);
            final String approvalRequestedByUpdated = (String) actualJsonObjectUpdated.get("requested_by");
            assertNotNull(approvalRequestedByUpdated);
            assertEquals("ApprovalRestResourceSystemTest", approvalRequestedByUpdated);
            final Boolean approvalRequestCanBeApprovedByMeUpdated = (Boolean) actualJsonObjectUpdated.get("can_be_approved_by_me");
            assertNotNull(approvalRequestCanBeApprovedByMeUpdated);

        } catch (Exception e) {
            throw new RuntimeException("Test setup failed. Could not add end entity", e);
        } finally {
            //  Clean up the extra approval request
            approvalSession.removeApprovalRequest(alwaysAllowToken, newApprovalRequestId);
        }
    }

    @Test
    public void testStatusShouldReturnErrorForInvalidRequest() throws Exception {
        // When: invalid request id is used
        final Response actualResponse = newRequest("/v1/approval/-12345/status").request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);

        // Then
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertEquals("Wrong error message", "Invalid request ID '-12345'. Request ID must be a positive integer.", actualJsonObject.get("error_message"));
    }

    @Test
    public void testStatusShouldReturnCorrectApprovalRequestStatus() throws Exception {
        // Given
        final int approvalRequestId = 12345;
        final int expectedStatus = ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
        final ApprovalRequestStatus expectedApprovalStatus = ApprovalRequestStatus.PENDING;

        final RaApprovalRequestInfo mockApprovalRequestInfo = EasyMock.createMock(RaApprovalRequestInfo.class);
        EasyMock.expect(mockApprovalRequestInfo.getStatus()).andReturn(expectedStatus).anyTimes();
        EasyMock.expect(mockApprovalRequestInfo.getId()).andReturn(approvalRequestId).anyTimes();
        EasyMock.replay(mockApprovalRequestInfo);

        EasyMock.expect(raMasterApiSessionMock.getApprovalRequest(EasyMock.anyObject(AuthenticationToken.class), EasyMock.eq(approvalRequestId)))
                .andReturn(mockApprovalRequestInfo);
        EasyMock.replay(raMasterApiSessionMock);

        // When
        final Response actualResponse = mockRestServer.newRequest("/v1/approval/" + approvalRequestId + "/status").request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);

        // Then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertEquals("Wrong approval request id returned", (long) approvalRequestId, actualJsonObject.get("request_id"));
        assertEquals(expectedApprovalStatus.getValue(), actualJsonObject.get("status"));

        EasyMock.verify(raMasterApiSessionMock);
        EasyMock.verify(mockApprovalRequestInfo);
    }

    @Test
    public void testProcessApprovalRequestApprove() throws Exception {
        // Given
        final String requestBody = "{" +
                "\"approve\": true," +
                "\"comment\": \"testProcessApprovalRequestApprove\"" +
                "}";

        // When
        final Response actualResponse = newRequest("/v1/approval/" + addEndEntityApprovalRequestId + "/process")
                .request()
                .post(Entity.entity(requestBody, "application/json"));
        final String actualJsonString = actualResponse.readEntity(String.class);

        // Then
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray steps = (JSONArray) actualJsonObject.get("steps");
        final JSONObject step = (JSONObject) steps.get(0);
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertEquals(String.valueOf(addEndEntityApprovalRequestId), actualJsonObject.get("request_id"));
        assertEquals("Add End Entity", actualJsonObject.get("request_type"));
        assertEquals(eeName, actualJsonObject.get("end_entity_name"));
        assertEquals("APPROVED", actualJsonObject.get("status"));
        // Verify approval step
        assertNotNull("Steps should not be null", steps);
        assertEquals("Should have one approval step", 1, steps.size());
        assertEquals("Step number should be 1", 1L, step.get("step"));
        assertEquals("Approval action should be APPROVED", "APPROVED", step.get("approval_action"));
        assertNotNull("Approval date should be present", step.get("approval_date"));
        assertEquals("Approval admin should be present", CERTIFICATE_SUBJECT_DN, step.get("approval_admin"));
        assertEquals("Approval comment should match", "testProcessApprovalRequestApprove", step.get("approval_comment"));

        // Verify approval was actually processed internally
        final ApprovalDataVO approvalData = approvalSession.findApprovalDataByRequestId(addEndEntityApprovalRequestId);
        assertEquals(ApprovalDataVO.STATUS_EXECUTED, approvalData.getStatus());
    }

    @Test
    public void testProcessApprovalRequestReject() throws Exception {
        // Given
        final String requestBody = "{" +
                "\"approve\": false," +
                "\"comment\": \"Test rejection comment\"" +
                "}";

        // When
        final Response actualResponse = newRequest("/v1/approval/" + addEndEntityApprovalRequestId + "/process")
                .request()
                .post(Entity.entity(requestBody, "application/json"));
        final String actualJsonString = actualResponse.readEntity(String.class);

        // Then
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertEquals(String.valueOf(addEndEntityApprovalRequestId), actualJsonObject.get("request_id"));
        assertEquals("Add End Entity", actualJsonObject.get("request_type"));
        assertEquals(eeName, actualJsonObject.get("end_entity_name"));
        assertEquals(ApprovalRequestStatus.REJECTED.getValue(), actualJsonObject.get("status"));

        // Verify approval was rejected (internal status STATUS_EXECUTIONDENIED)
        final ApprovalDataVO approvalData = approvalSession.findApprovalDataByRequestId(addEndEntityApprovalRequestId);
        assertEquals(ApprovalDataVO.STATUS_EXECUTIONDENIED, approvalData.getStatus());
    }

    @Test
    public void testProcessApprovalRequestNotFound() throws Exception {
        // Given
        final int nonExistentRequestId = 999999;
        final String requestBody = "{" +
                "\"approve\": true," +
                "\"comment\": \"Test comment\"" +
                "}";

        // When
        final Response actualResponse = newRequest("/v1/approval/" + nonExistentRequestId + "/process")
                .request()
                .post(Entity.entity(requestBody, "application/json"));

        // Then
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        assertEquals(Response.Status.NOT_FOUND.getStatusCode(), actualResponse.getStatus());
        assertEquals("Approval request with ID " + nonExistentRequestId + " not found or unauthorized", actualJsonObject.get("error_message"));
    }

    @Test
    public void testProcessApprovalRequestAlreadyProcessed() throws Exception {
        // Given
        final RaApprovalRequestInfo raApprovalRequestInfo = raMasterApiSession.getApprovalRequest(alwaysAllowToken, addEndEntityApprovalRequestId);

        final RaApprovalResponseRequest responseRequest = new RaApprovalResponseRequest(
                addEndEntityApprovalRequestId,
                raApprovalRequestInfo.getNextApprovalStep().getStepIdentifier(),
                raApprovalRequestInfo.getNextApprovalStepPartition().getPartitionIdentifier(),
                raApprovalRequestInfo.getApprovalRequest(),
                "testProcessApprovalRequestApprove",
                RaApprovalResponseRequest.Action.APPROVE
        );
        raMasterApiSession.addRequestResponse(alwaysAllowToken, responseRequest);

        final String requestBody = "{" +
                "\"approve\": true," +
                "\"comment\": \"Second approval attempt\"" +
                "}";
        // When
        final Response actualResponse = newRequest("/v1/approval/" + addEndEntityApprovalRequestId + "/process")
                .request()
                .post(Entity.entity(requestBody, "application/json"));

        // Then
        assertEquals(Response.Status.CONFLICT.getStatusCode(), actualResponse.getStatus());
    }
}