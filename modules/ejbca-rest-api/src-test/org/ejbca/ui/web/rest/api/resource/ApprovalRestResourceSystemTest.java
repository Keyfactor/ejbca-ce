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
import jakarta.ws.rs.core.Response;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.junit.util.TraceLogMethodsTestWatcher;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.easymock.EasyMock;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequestStatus;
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

import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;

@RunWith(EasyMockRunner.class)
public class ApprovalRestResourceSystemTest extends RestResourceSystemTestBase {

    private static final Logger log = Logger.getLogger(ApprovalRestResourceSystemTest.class);
    private static final JSONParser jsonParser = new JSONParser();

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
        RestResourceSystemTestBase.beforeClass();
    }

    @Before
    public void before() throws Exception {
        mockRestServer = InMemoryRestServer.create(mockRestResource);
        mockRestServer.start();
    }

    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
    }

    @After
    public void after() {
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
}
