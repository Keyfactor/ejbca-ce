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
package org.ejbca.ui.web.rest.api.resource;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Arrays;
import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.*;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.junit.util.TraceLogMethodsTestWatcher;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.ui.DynamicUiProperty;
import org.cesecore.util.ui.RadioButton;
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
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.approval.profile.PartitionedApprovalProfile;
import org.ejbca.core.model.era.*;
import org.ejbca.ui.web.rest.api.InMemoryRestServer;
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
import static org.junit.Assert.assertFalse;
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
    private String partitionedEeName;
    private Integer addEndEntityApprovalRequestId;
    private Integer addEndEntityPartitionedApprovalRequestId;
    private static Integer caId;
    private static Integer partitionedCaId;
    private static Integer accumulativeApprovalProfileId;
    private static Integer partitionedApprovalProfileId;

    private static final String CA_NAME = "ApprovalRestResourceSystemTest_CA";
    private static final String CA_NAME_PARTITIONED = "ApprovalRestResourceSystemTest_Partitioned_CA";
    private static final String APPROVAL_PROFILE_NAME = "ApprovalRestResourceSystemTest_APPROVAL_PROFILE";
    private static final String PARTITIONED_APPROVAL_PROFILE_NAME = "PartitionedApprovalRestResourceSystemTest_APPROVAL_PROFILE";

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
        // Create test CA for Partitioned Approval profile
        X509CA testPartitionedCa = CaTestUtils.createTestX509CA("CN=" + CA_NAME_PARTITIONED, "foo123".toCharArray(), false);
        caSession.addCA(alwaysAllowToken, testPartitionedCa);
        CAInfo testPartitionedCaInfo = testPartitionedCa.getCAInfo();
        partitionedCaId = testPartitionedCaInfo.getCAId();
        // Create Approval Profile
        final AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile(APPROVAL_PROFILE_NAME);
        approvalProfile.setNumberOfApprovalsRequired(1);
        accumulativeApprovalProfileId = approvalProfileSession.addApprovalProfile(alwaysAllowToken, approvalProfile);
        // Create Partitioned Approval Profile
        final PartitionedApprovalProfile partitionedApprovalProfile = new PartitionedApprovalProfile(PARTITIONED_APPROVAL_PROFILE_NAME);
        partitionedApprovalProfile.addStepFirst();
        ApprovalStep firstStep = partitionedApprovalProfile.getFirstStep();
        ApprovalPartition firstStepPartition = firstStep.getPartitions().values().iterator().next();
        final DynamicUiProperty<RadioButton>  property = new DynamicUiProperty<>("Radio test", new RadioButton("Blue"),
                new ArrayList<RadioButton>( Arrays.asList(new RadioButton("Green"), new RadioButton("Blue"), new RadioButton("Red"))));
        property.setType(RadioButton.class);
        partitionedApprovalProfile.addPropertyToPartition(firstStep.getStepIdentifier(), firstStepPartition.getPartitionIdentifier(), property);

        partitionedApprovalProfileId = approvalProfileSession.addApprovalProfile(alwaysAllowToken, partitionedApprovalProfile);
        // Apply Approval Profile to CA
        Map<ApprovalRequestType, Integer> approvalSettings = testCaInfo.getApprovals();
        approvalSettings.put(ApprovalRequestType.ADDEDITENDENTITY, accumulativeApprovalProfileId);
        testCaInfo.setApprovals(approvalSettings);
        caSession.editCA(alwaysAllowToken, testCaInfo);
        approvalSettings = testPartitionedCaInfo.getApprovals();
        approvalSettings.put(ApprovalRequestType.ADDEDITENDENTITY, partitionedApprovalProfileId);
        testPartitionedCaInfo.setApprovals(approvalSettings);
        caSession.editCA(alwaysAllowToken, testPartitionedCaInfo);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
        CaTestUtils.removeCa(alwaysAllowToken, "CN=" + CA_NAME, CA_NAME);
        CaTestUtils.removeCa(alwaysAllowToken, "CN=" + CA_NAME_PARTITIONED, CA_NAME_PARTITIONED);
        approvalProfileSession.removeApprovalProfile(alwaysAllowToken, accumulativeApprovalProfileId);
        approvalProfileSession.removeApprovalProfile(alwaysAllowToken, partitionedApprovalProfileId);
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
        // Trigger an add end entity for partitioned approval
        partitionedEeName = this.getClass().getName() + "_ee_" + System.currentTimeMillis();
        userdata = new EndEntityInformation(partitionedEeName, "CN=" + partitionedEeName, partitionedCaId, null, null, new EndEntityType(
                EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityConstants.TOKEN_SOFT_P12, null);
        userdata.setPassword("foo123");
        try {
            endEntityManagementSession.addUser(alwaysAllowToken, userdata, true);
        } catch (WaitingForApprovalException e) {
            // Capture the requestId
            addEndEntityPartitionedApprovalRequestId = e.getRequestId();
        } catch (Exception e) {
            throw new RuntimeException("Test setup failed. Could not add end entity", e);
        }
    }

    @After
    public void after() throws Exception {
        // Remove approval requests
        approvalSession.removeApprovalRequest(alwaysAllowToken, addEndEntityApprovalRequestId);
        approvalSession.removeApprovalRequest(alwaysAllowToken, addEndEntityPartitionedApprovalRequestId);
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
        assertEquals("Step number should be 1", 1L, step.get("step_number"));
        final JSONArray partitions = (JSONArray) step.get("partition_list");
        final JSONObject partition = (JSONObject) partitions.get(0);
        assertEquals("Approval action should be APPROVED", "APPROVED", partition.get("approval_action"));
        assertNotNull("Approval date should be present", partition.get("approval_date"));
        assertEquals("Approval admin should be present", CERTIFICATE_SUBJECT_DN, partition.get("approval_admin"));
        assertEquals("Approval comment should match", "testProcessApprovalRequestApprove", partition.get("approval_comment"));

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


    @Test
    public void testDataShouldReturnErrorForInvalidRequest() throws Exception {
        // When: invalid request id is used
        final Response actualResponse = newRequest("/v1/approval/-12345").request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);

        // Then
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertEquals("Wrong error message", "Invalid request ID '-12345'. Request ID must be a positive integer.", actualJsonObject.get("error_message"));
    }

    @Test
    public void testApprovalDataRequest() throws Exception {
        // Given


        // When
        final Response actualResponse = newRequest("/v1/approval/" + addEndEntityApprovalRequestId)
                .request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);

        // Then
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray steps = (JSONArray) actualJsonObject.get("steps");
        final JSONObject nextStep = (JSONObject) actualJsonObject.get("next_step");
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertEquals(String.valueOf(addEndEntityApprovalRequestId), actualJsonObject.get("request_id"));
        assertEquals("Add End Entity", actualJsonObject.get("request_type"));
        assertEquals(eeName, actualJsonObject.get("end_entity_name"));
        assertEquals("PENDING", actualJsonObject.get("status"));
        // Verify approval step
        assertNotNull("Steps should not be null", steps);
        assertNotNull("Next step should not be null", nextStep);
        assertEquals("Should have none approved step", 0, steps.size());
        assertEquals("Step number should be 1", 1L, nextStep.get("step_number"));
        final JSONArray partitions = (JSONArray) nextStep.get("partition_list");
        final JSONObject partition = (JSONObject) partitions.get(0);
        assertEquals("Approval action should be PENDING", "PENDING", partition.get("approval_action"));
        assertEquals(EndEntityTypes.ENDUSER.toString(), actualJsonObject.get("certificate_profile_name"));
        assertEquals("Approval EEP should be EMPTY", "EMPTY", actualJsonObject.get("end_entity_profile_name"));
        assertEquals("Approval EEP should be subject dn is incorrect", "CN="+eeName, actualJsonObject.get("subject_dn"));
        assertEquals("Approval CA name is incorrect",  CA_NAME, actualJsonObject.get("ca_name"));
        assertEquals("Approval key_recoverable is incorrect","NO", actualJsonObject.get("key_recoverable"));
        assertFalse("Approval subject_name_log_redaction is incorrect", Boolean.getBoolean(actualJsonObject.get("subject_name_log_redaction").toString()));
        assertEquals("Approval send_notification is incorrect","NO", actualJsonObject.get("send_notification"));


        // Verify approval was actually processed internally
        final ApprovalDataVO approvalData = approvalSession.findApprovalDataByRequestId(addEndEntityApprovalRequestId);
        assertEquals("Approval status is incorrect", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, approvalData.getStatus());
    }

    @Test
    public void testPartitionedApprovalDataRequest() throws Exception {
        // Given

        // When
        final Response actualResponse = newRequest("/v1/approval/" + addEndEntityPartitionedApprovalRequestId)
                .request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);

        // Then
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray steps = (JSONArray) actualJsonObject.get("steps");
        final JSONObject nextStep = (JSONObject) actualJsonObject.get("next_step");
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertEquals("Request id should match", String.valueOf(addEndEntityPartitionedApprovalRequestId), actualJsonObject.get("request_id"));
        assertEquals("Request type should be Add End Entity","Add End Entity", actualJsonObject.get("request_type"));
        assertEquals("End Entity name should be correct", partitionedEeName, actualJsonObject.get("end_entity_name"));
        assertEquals("PENDING", actualJsonObject.get("status"));
        // Verify approval step
        assertNotNull("Steps should not be null", steps);
        assertNotNull("Next step should not be null", nextStep);
        assertEquals("Should have none approved step", 0, steps.size());
        assertEquals("Step number should be 1", 1L, nextStep.get("step_number"));
        final JSONArray partitions = (JSONArray) nextStep.get("partition_list");
        final JSONObject partition = (JSONObject) partitions.get(0);
        assertEquals("Approval action should be PENDING", "PENDING", partition.get("approval_action"));
        final JSONArray properties = (JSONArray) partition.get("property_list");
        assertEquals("Should have one property", 1, properties.size());
        final JSONObject property = (JSONObject) properties.get(0);
        assertEquals("Property label ", "Radio test", property.get("label"));
        assertEquals("Property type ", "RadioButton", property.get("type"));
        assertEquals("Property value ", "Blue", property.get("value"));
        final JSONArray possibleValues = (JSONArray) property.get("possible_values");
        assertEquals("Should have 3 possible values", 3, possibleValues.size());

        assertEquals("Approval certificate profile be ENDUSER", EndEntityTypes.ENDUSER.toString(), actualJsonObject.get("certificate_profile_name"));
        assertEquals("Approval EEP should be EMPTY", "EMPTY", actualJsonObject.get("end_entity_profile_name"));
        assertEquals("Approval EEP should be subject dn is incorrect", "CN="+partitionedEeName, actualJsonObject.get("subject_dn"));
        assertEquals("Approval CA name is incorrect",  CA_NAME_PARTITIONED, actualJsonObject.get("ca_name"));
        assertEquals("Approval key_recoverable is incorrect","NO", actualJsonObject.get("key_recoverable"));
        assertFalse("Approval subject_name_log_redaction is incorrect", Boolean.getBoolean(actualJsonObject.get("subject_name_log_redaction").toString()));
        assertEquals("Approval send_notification is incorrect","NO", actualJsonObject.get("send_notification"));


        // Verify approval was actually processed internally
        final ApprovalDataVO approvalData = approvalSession.findApprovalDataByRequestId(addEndEntityApprovalRequestId);
        assertEquals("Approval status is incorrect", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, approvalData.getStatus());
    }
}