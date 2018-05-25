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

import static org.easymock.EasyMock.anyBoolean;
import static org.easymock.EasyMock.anyInt;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response.Status;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.easymock.EasyMock;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.ui.web.rest.api.InMemoryRestServer;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.ClientResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * A unit test class for CertificateRestResource to test its content.
 * <br/>
 * The testing is organized through deployment of this resource with mocked dependencies into InMemoryRestServer.
 *
 * @version $Id: CertificateRestResourceUnitTest.java 28909 2018-05-21 12:16:53Z andrey_s_helmes $
 * @see org.ejbca.ui.web.rest.api.InMemoryRestServer
 */
@RunWith(EasyMockRunner.class)
public class CertificateRestResourceUnitTest {

    private static final JSONParser jsonParser = new JSONParser();
    private static final AuthenticationToken authenticationToken = new UsernameBasedAuthenticationToken(new UsernamePrincipal("TestRunner"));
    // Extend class to test without security
    private static class CertificateRestResourceWithoutSecurity extends CertificateRestResource {
        @Override
        protected AuthenticationToken getAdmin(HttpServletRequest requestContext, boolean allowNonAdmins) throws AuthorizationDeniedException {
            return authenticationToken;
        }
    }
    
    public static InMemoryRestServer server;
    
    @TestSubject
    private static CertificateRestResourceWithoutSecurity testClass = new CertificateRestResourceWithoutSecurity();

    @Mock
    private EjbBridgeSessionLocal ejbLocalHelper;
    
    @Mock
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSessionLocal;

    @Mock
    private RaMasterApiProxyBeanLocal raMasterApiProxy;

    @Mock
    HttpServletRequest requestContext;
    
    @BeforeClass
    public static void beforeClass() throws IOException {
        server = InMemoryRestServer.create(testClass);
        server.start();
    }

    @AfterClass
    public static void afterClass() {
        server.close();
    }

    private String getContentType(final ClientResponse<?> clientResponse) {
        final MultivaluedMap<String, String> headersMap = clientResponse.getHeaders();
        if (headersMap != null) {
            return headersMap.getFirst("Content-type");
        }
        return null;
    }

    @Test
    public void shouldReturnProperStatus() throws Exception {
        // given
        final String expectedStatus = "OK";
        final String expectedVersion = "1.0";
        final String expectedRevision = "ALPHA";
        // when
        ClientRequest newRequest = server.newRequest("/v1/certificate/status");
        final ClientResponse<?> actualResponse = newRequest.get();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualStatus = actualJsonObject.get("status");
        final Object actualVersion = actualJsonObject.get("version");
        final Object actualRevision = actualJsonObject.get("revision");
        // then
        assertEquals(Status.OK.getStatusCode(), actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualStatus);
        assertEquals(expectedStatus, actualStatus);
        assertNotNull(actualVersion);
        assertEquals(expectedVersion, actualVersion);
        assertNotNull(actualRevision);
        assertEquals(expectedRevision, actualRevision);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithAuthorizationDeniedException() throws Exception {
        // given
        final int expectedErrorCode = Status.FORBIDDEN.getStatusCode();
        final String expectedErrorMessage = "This is AuthorizationDeniedException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new AuthorizationDeniedException(expectedErrorMessage));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse<?> actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithRestException() throws Exception {
        // given
        final int expectedErrorCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedErrorMessage = "Invalid revocation reason.";
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", "BAD_REVOCATION_REASON_DOES_NOT_EXIST");
        final ClientResponse<?> actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithNoSuchEndEntityException() throws Exception {
        // given
        final int expectedErrorCode = Status.NOT_FOUND.getStatusCode();
        final String expectedErrorMessage = "This is NoSuchEndEntityException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new NoSuchEndEntityException(expectedErrorMessage));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse<?> actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithAlreadyRevokedException() throws Exception {
        // given
        final int expectedErrorCode = Status.CONFLICT.getStatusCode();
        final String expectedErrorMessage = "This is AlreadyRevokedException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new AlreadyRevokedException(expectedErrorMessage));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse<?> actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithWaitingForApprovalException() throws Exception {
        // given
        final int expectedErrorCode = Status.ACCEPTED.getStatusCode();
        final String expectedErrorMessage = "This is WaitingForApprovalException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new WaitingForApprovalException(expectedErrorMessage, 1));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse<?> actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithApprovalException() throws Exception {
        // given
        final int expectedErrorCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedErrorMessage = "This is ApprovalException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new ApprovalException(expectedErrorMessage));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse<?> actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithRevokeBackDateNotAllowedForProfileException() throws Exception {
        // given
        final int expectedErrorCode = 422;
        final String expectedErrorMessage = "This is RevokeBackDateNotAllowedForProfileException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new RevokeBackDateNotAllowedForProfileException(expectedErrorMessage));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse<?> actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithCADoesntExistsException() throws Exception {
        // given
        final int expectedErrorCode = Status.NOT_FOUND.getStatusCode();
        final String expectedErrorMessage = "This is CADoesntExistsException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new CADoesntExistsException(expectedErrorMessage));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse<?> actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnNoMoreExpiredCertificates() throws Exception {
        // given
        long days = 1;
        int offset = 0;
        int maxNumberOfResults = 0;

        expect(raMasterApiProxy.getCountOfCertificatesByExpirationTime((AuthenticationToken)EasyMock.anyObject(), anyInt())).andReturn(0).times(1);
        expect(raMasterApiProxy.getCertificatesByExpirationTime((AuthenticationToken)EasyMock.anyObject(), eq(days), eq(maxNumberOfResults), eq(offset)))
                .andReturn(Collections.<Certificate>emptyList());

        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/expire")
                .queryParameter("days", days)
                .queryParameter("offset", offset)
                .queryParameter("maxNumberOfResults", maxNumberOfResults);
        final ClientResponse<?> actualResponse = clientRequest.get();
        Status status = actualResponse.getResponseStatus();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final boolean moreResults  = (Boolean) ((JSONObject)actualJsonObject.get("responseStatus")).get("moreResults");
        // then
        assertEquals(Status.OK, status);
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertFalse(moreResults);
        EasyMock.verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnAreMoreResultsAndNextOffsetAndNumberOfResultsLeft() throws Exception {
        // given
        long days = 1;
        int offset = 0;
        int maxNumberOfResults = 4;
        long expectedNextOffset = 4l;
        long expectedNumberOfResults = 6l;

        expect(raMasterApiProxy.getCountOfCertificatesByExpirationTime((AuthenticationToken)EasyMock.anyObject(), anyInt())).andReturn(10).times(1);
        expect(raMasterApiProxy.getCertificatesByExpirationTime((AuthenticationToken)EasyMock.anyObject(), eq(days), eq(maxNumberOfResults), eq(offset)))
                .andReturn(Collections.<Certificate>emptyList());

        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/expire")
                .queryParameter("days", days)
                .queryParameter("offset", offset)
                .queryParameter("maxNumberOfResults", maxNumberOfResults);
        final ClientResponse<?> actualResponse = clientRequest.get();
        Status status = actualResponse.getResponseStatus();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        JSONObject responseStatus = (JSONObject) actualJsonObject.get("responseStatus");
        final boolean moreResults  = (Boolean) responseStatus.get("moreResults");
        final long nextOffset  = (Long) responseStatus.get("nextOffset");
        final long numberOfResults  = (Long) responseStatus.get("numberOfResults");
        // then
        assertEquals(Status.OK, status);
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertTrue(moreResults);
        assertEquals(expectedNextOffset, nextOffset);
        assertEquals(expectedNumberOfResults, numberOfResults);
        EasyMock.verify(raMasterApiProxy);
    }


    @Test
    public void shouldReturnAreMoreResultsAndNextOffsetAndNumberOfResultsLeftWithNotZeroOffset() throws Exception {
        // given
        long days = 1;
        int offset = 3;
        int maxNumberOfResults = 4;
        long expectedNextOffset = 7l;
        long expectedNumberOfResults = 3l;

        expect(raMasterApiProxy.getCountOfCertificatesByExpirationTime((AuthenticationToken)EasyMock.anyObject(), anyInt())).andReturn(10).times(1);
        expect(raMasterApiProxy.getCertificatesByExpirationTime((AuthenticationToken)EasyMock.anyObject(), eq(days), eq(maxNumberOfResults), eq(offset)))
                .andReturn(Collections.<Certificate>emptyList());

        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/expire")
                .queryParameter("days", days)
                .queryParameter("offset", offset)
                .queryParameter("maxNumberOfResults", maxNumberOfResults);
        final ClientResponse<?> actualResponse = clientRequest.get();
        Status status = actualResponse.getResponseStatus();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        JSONObject responseStatus = (JSONObject) actualJsonObject.get("responseStatus");
        final boolean moreResults  = (Boolean) responseStatus.get("moreResults");
        final long nextOffset  = (Long) responseStatus.get("nextOffset");
        final long numberOfResults  = (Long) responseStatus.get("numberOfResults");
        // then
        assertEquals(Status.OK, status);
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertTrue(moreResults);
        assertEquals(expectedNextOffset, nextOffset);
        assertEquals(expectedNumberOfResults, numberOfResults);
        EasyMock.verify(raMasterApiProxy);
    }
}
