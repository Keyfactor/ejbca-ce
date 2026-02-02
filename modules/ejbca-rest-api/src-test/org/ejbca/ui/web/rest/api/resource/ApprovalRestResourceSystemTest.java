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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.*;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
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
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequestStatus;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.InMemoryRestServer;
import org.ejbca.ui.web.rest.api.resource.swagger.ApprovalRestResourceSwagger;
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
    private final ApprovalExecutionSessionRemote approvalExecutionSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalExecutionSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);

 private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ApprovalRestResourceSystemTest"));
    
    private String eeName;
    private Integer addEndEntityApprovalRequestId;
    private static Integer caId;
    private static Integer accumulativeApprovalProfileId;

    private static final String CA_NAME = "ApprovalRestResourceSystemTest_CA";
    private static final String APPROVAL_PROFILE_NAME = "ApprovalRestResourceSystemTest_APPROVAL_PROFILE";

    @Mock
    private RaMasterApiProxyBeanLocal raMasterApiSession;

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
    public void setUp() throws Exception {
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
    public void tearDown() throws Exception {
        // Remove approval requests
        approvalSession.removeApprovalRequest(alwaysAllowToken, addEndEntityApprovalRequestId);
	    // Kill REST Server
        if (mockRestServer != null) {
            mockRestServer.close();
        }
    }



    @Test
    public void testNothing() {
        assertNotNull("Approval was not added", addEndEntityApprovalRequestId);
        System.out.println("Approval was added with requestId: " + addEndEntityApprovalRequestId);
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
    public void testStatusShouldReturnCorrectApprovalRequestStatus() throws Exception {
        // Given
        final int approvalRequestId = 12345;
        final int expectedStatus = ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
        final ApprovalRequestStatus expectedApprovalStatus = ApprovalRequestStatus.PENDING;

        final RaApprovalRequestInfo mockApprovalRequestInfo = EasyMock.createMock(RaApprovalRequestInfo.class);
        EasyMock.expect(mockApprovalRequestInfo.getStatus()).andReturn(expectedStatus).anyTimes();
        EasyMock.expect(mockApprovalRequestInfo.getId()).andReturn(approvalRequestId).anyTimes();
        EasyMock.replay(mockApprovalRequestInfo);

        EasyMock.expect(raMasterApiSession.getApprovalRequest(EasyMock.anyObject(AuthenticationToken.class), EasyMock.eq(approvalRequestId)))
                .andReturn(mockApprovalRequestInfo);
        EasyMock.replay(raMasterApiSession);

        // When
        final Response actualResponse = mockRestServer.newRequest("/v1/approval/" + approvalRequestId + "/status").request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);

        // Then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertEquals("Wrong approval request id returned", (long) approvalRequestId, actualJsonObject.get("request_id"));
        assertEquals(expectedApprovalStatus.getValue(), actualJsonObject.get("status"));

        EasyMock.verify(raMasterApiSession);
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
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertEquals(String.valueOf(addEndEntityApprovalRequestId), actualJsonObject.get("request_id"));
        assertEquals("Add End Entity", actualJsonObject.get("request_type"));
        assertEquals(eeName, actualJsonObject.get("end_entity_name"));
        assertEquals("APPROVED", actualJsonObject.get("status"));

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
        assertEquals("REJECTED", actualJsonObject.get("status"));

        // Verify approval was rejected
        final ApprovalDataVO approvalData = approvalSession.findApprovalDataByRequestId(addEndEntityApprovalRequestId);
        assertEquals(ApprovalDataVO.STATUS_REJECTED, approvalData.getStatus());
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
        assertEquals("Wrong error message", "Invalid request ID: -12345. Request ID must be a positive integer.", actualJsonObject.get("error_message"));
    }

    @Test
    public void testProcessApprovalRequestNotFound() throws Exception {
        // given
        final int nonExistentRequestId = 999999;
        final String requestBody = "{" +
                "\"approve\": true," +
                "\"comment\": \"Test comment\"" +
                "}";

        // when
        final Response actualResponse = newRequest("/v1/approval/" + nonExistentRequestId + "/process")
                .request()
                .post(Entity.entity(requestBody, "application/json"));

        // then
        final String actualJsonString = actualResponse.readEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        assertEquals(Response.Status.NOT_FOUND.getStatusCode(), actualResponse.getStatus());
        assertEquals("Approval request with ID " + nonExistentRequestId + " not found or unauthorized", actualJsonObject.get("error_message"));
    }
//
//    @Test
//    public void testProcessApprovalRequestAlreadyProcessed() throws Exception {
//        // given
//        setupTestData();
//
//        // First approve the request
//        final String firstRequestBody = "{" +
//                "\"approve\": true," +
//                "\"comment\": \"First approval\"" +
//                "}";
//        newRequest("/v1/approval/request/" + testApprovalRequestId)
//                .request()
//                .post(Entity.entity(firstRequestBody, "application/json"));
//
//        // Try to process again
//        final String secondRequestBody = "{" +
//                "\"approve\": true," +
//                "\"comment\": \"Second approval attempt\"" +
//                "}";
//
//        // when
//        final Response actualResponse = newRequest("/v1/approval/request/" + testApprovalRequestId)
//                .request()
//                .post(Entity.entity(secondRequestBody, "application/json"));
//
//        // then
//        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), actualResponse.getStatus());
//    }

}
