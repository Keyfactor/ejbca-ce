/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.config;

import static org.easymock.EasyMock.anyInt;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonExceptionErrorResponse;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonExceptionInfoResponse;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;

import javax.ejb.Stateless;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.certificatetransparency.CTLogException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.util.StreamSizeLimitExceededException;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.EndEntityProfileValidationRaException;
import org.ejbca.core.model.ra.KeyStoreGeneralRaException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.ui.web.rest.api.InMemoryRestServer;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.resource.BaseRestResource;
import org.jboss.resteasy.client.ClientResponse;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * A unit test class for ExceptionHandler to test correctness of mapping between Exception and Error/Info response.
 *
 * @version $Id: ExceptionHandler.java 29080 2018-05-31 11:12:13Z andrey_s_helmes $
 */
@RunWith(EasyMockRunner.class)
public class ExceptionHandlerUnitTest {

    public static InMemoryRestServer server;

    public static class DummyMock {
        public int throwException(int i) throws Exception {
            return i;
        }
    }

    @Path("v1/dummy")
    @Stateless
    public static class DummyRestResource extends BaseRestResource {

        private DummyMock dummyMock = new DummyMock();

        @GET
        public Response throwsException() throws Exception {
            dummyMock.throwException(0);
            return Response.ok("{\"message\":\"ok\"}").build();
        }
    }

    @Mock
    private DummyMock dummyMock;

    @TestSubject
    private static DummyRestResource testClass = new DummyRestResource();

    @BeforeClass
    public static void beforeClass() throws IOException {
        server = InMemoryRestServer.create(testClass);
        server.start();
    }

    @AfterClass
    public static void afterClass() {
        server.close();
    }

    // -----------------------------------------------------------------------------------------------------------------
    // General Exceptions
    // -----------------------------------------------------------------------------------------------------------------
    // 400
    @Test
    public void shouldFormProperErrorResponseOnRestException() throws Exception {
        // given
        final long expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "RestException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new RestException((int)expectedCode, expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 404
    @Test
    public void shouldFormProperErrorResponseOnWebApplicationException() throws Exception {
        // given
        final long expectedCode = Status.NOT_FOUND.getStatusCode();
        final String expectedMessage = "The requested path was not found";
        // WebApplicationException will be apparently reach our custom ExceptionHandler unwrapped, but the message and code seems to be set already
        final String expectedErrorMessage = "HTTP 404 Not Found";
        expect(dummyMock.throwException(anyInt())).andThrow(new WebApplicationException(new Exception(expectedMessage), (int) expectedCode));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedErrorMessage, actualJson);
        verify(dummyMock);
    }

    // 500
    @Test
    public void shouldFormProperErrorResponseOnException() throws Exception {
        // given
        final long expectedCode = Status.INTERNAL_SERVER_ERROR.getStatusCode();
        final String expectedMessage = ExceptionHandler.DEFAULT_ERROR_MESSAGE;
        expect(dummyMock.throwException(anyInt())).andThrow(new Exception());
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // -----------------------------------------------------------------------------------------------------------------
    // EjbcaExceptionClasses
    // -----------------------------------------------------------------------------------------------------------------
    // 400
    @Test
    public void shouldFormProperErrorResponseOnApprovalException() throws Exception {
        // given
        final long expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "ApprovalException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new ApprovalException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnKeyStoreGeneralRaException() throws Exception {
        // given
        final long expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String message = "KeyStoreGeneralRaException error message";
        final String expectedMessage = "java.lang.Exception: " + message;
        Exception exception = new Exception(message);
        expect(dummyMock.throwException(anyInt())).andThrow(new KeyStoreGeneralRaException(exception));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 403
    @Test
    public void shouldFormProperErrorResponseOnAuthLoginException() throws Exception {
        // given
        final long expectedCode = Status.FORBIDDEN.getStatusCode();
        final String expectedMessage = "AuthLoginException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new AuthLoginException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnAuthStatusException() throws Exception {
        // given
        final long expectedCode = Status.FORBIDDEN.getStatusCode();
        final String expectedMessage = "AuthStatusException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new AuthStatusException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 404
    @Test
    public void shouldFormProperErrorResponseOnNotFoundException() throws Exception {
        // given
        final long expectedCode = Status.NOT_FOUND.getStatusCode();
        final String expectedMessage = "NotFoundException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new NotFoundException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 409
    @Test
    public void shouldFormProperErrorResponseOnAlreadyRevokedException() throws Exception {
        // given
        final long expectedCode = Status.CONFLICT.getStatusCode();
        final String expectedMessage = "AlreadyRevokedException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new AlreadyRevokedException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 422
    @Test
    public void shouldFormProperErrorResponseOnCustomFieldException() throws Exception {
        // given
        final long expectedCode = 422;
        final String expectedMessage = "CustomFieldException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new CustomFieldException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnEndEntityProfileValidationRaException() throws Exception {
        // given
        final long expectedCode = 422;
        final String message = "EndEntityProfileValidationRaException error message";
        final String expectedMessage = "org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException: " + message;
        EndEntityProfileValidationException exception = new EndEntityProfileValidationException(message);
        expect(dummyMock.throwException(anyInt())).andThrow(new EndEntityProfileValidationRaException(exception));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnRevokeBackDateNotAllowedForProfileException() throws Exception {
        // given
        final long expectedCode = 422;
        final String expectedMessage = "RevokeBackDateNotAllowedForProfileException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new RevokeBackDateNotAllowedForProfileException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // -----------------------------------------------------------------------------------------------------------------
    // CesecoreExceptionClasses
    // -----------------------------------------------------------------------------------------------------------------
    // 400
    @Test
    public void shouldFormProperErrorResponseOnCertificateRevokeException() throws Exception {
        // given
        final long expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "CertificateRevokeException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new CertificateRevokeException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnCertificateSerialNumberException() throws Exception {
        // given
        final long expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "CertificateSerialNumberException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new CertificateSerialNumberException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnEndEntityExistsException() throws Exception {
        // given
        final long expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "EndEntityExistsException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new EndEntityExistsException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 404
    @Test
    public void shouldFormProperErrorResponseOnCADoesntExistsException() throws Exception {
        // given
        final long expectedCode = Status.NOT_FOUND.getStatusCode();
        final String expectedMessage = "CADoesntExistsException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new CADoesntExistsException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnCertificateProfileDoesNotExistException() throws Exception {
        // given
        final long expectedCode = Status.NOT_FOUND.getStatusCode();
        final String expectedMessage = "CertificateProfileDoesNotExistException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new CertificateProfileDoesNotExistException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnNoSuchEndEntityException() throws Exception {
        // given
        final long expectedCode = Status.NOT_FOUND.getStatusCode();
        final String expectedMessage = "NoSuchEndEntityException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new NoSuchEndEntityException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 422
    @Test
    public void shouldFormProperErrorResponseOnIllegalNameException() throws Exception {
        // given
        final long expectedCode = 422;
        final String expectedMessage = "IllegalNameException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new IllegalNameException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnIllegalValidityException() throws Exception {
        // given
        final long expectedCode = 422;
        final String expectedMessage = "IllegalValidityException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new IllegalValidityException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnInvalidAlgorithmException() throws Exception {
        // given
        final long expectedCode = 422;
        final String expectedMessage = "InvalidAlgorithmException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new InvalidAlgorithmException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 500
    @Test
    public void shouldFormProperErrorResponseOnCertificateCreateException() throws Exception {
        // given
        final long expectedCode = Status.INTERNAL_SERVER_ERROR.getStatusCode();
        final String expectedMessage = ExceptionHandler.DEFAULT_ERROR_MESSAGE;
        expect(dummyMock.throwException(anyInt())).andThrow(new CertificateCreateException("Test"));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 503
    @Test
    public void shouldFormProperErrorResponseOnCAOfflineException() throws Exception {
        // given
        final long expectedCode = Status.SERVICE_UNAVAILABLE.getStatusCode();
        final String expectedMessage = "CAOfflineException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new CAOfflineException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnCryptoTokenOfflineException() throws Exception {
        // given
        final long expectedCode = Status.SERVICE_UNAVAILABLE.getStatusCode();
        final String expectedMessage = "CryptoTokenOfflineException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new CryptoTokenOfflineException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnCTLogException() throws Exception {
        // given
        final long expectedCode = Status.SERVICE_UNAVAILABLE.getStatusCode();
        final String expectedMessage = "CTLogException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new CTLogException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // -----------------------------------------------------------------------------------------------------------------
    // ExceptionClasses
    // -----------------------------------------------------------------------------------------------------------------
    // 202
    @Test
    public void shouldFormProperErrorResponseOnWaitingForApprovalException() throws Exception {
        // given
        final long expectedCode = Status.ACCEPTED.getStatusCode();
        final String expectedMessage = "WaitingForApprovalException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new WaitingForApprovalException(expectedMessage, 0));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionInfoResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 400
    @Test
    public void shouldFormProperErrorResponseOnApprovalRequestExecutionException() throws Exception {
        // given
        final long expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "ApprovalRequestExecutionException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new ApprovalRequestExecutionException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnApprovalRequestExpiredException() throws Exception {
        // given
        final long expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "ApprovalRequestExpiredException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new ApprovalRequestExpiredException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnRoleExistsException() throws Exception {
        // given
        final long expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "RoleExistsException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new RoleExistsException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 403
    @Test
    public void shouldFormProperErrorResponseOnAuthenticationFailedException() throws Exception {
        // given
        final long expectedCode = Status.FORBIDDEN.getStatusCode();
        final String expectedMessage = "AuthenticationFailedException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new AuthenticationFailedException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnAuthorizationDeniedException() throws Exception {
        // given
        final long expectedCode = Status.FORBIDDEN.getStatusCode();
        final String expectedMessage = "AuthorizationDeniedException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new AuthorizationDeniedException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnSelfApprovalException() throws Exception {
        // given
        final long expectedCode = Status.FORBIDDEN.getStatusCode();
        final String expectedMessage = "SelfApprovalException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new SelfApprovalException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 404
    @Test
    public void shouldFormProperErrorResponseOnEndEntityProfileNotFoundException() throws Exception {
        // given
        final long expectedCode = Status.NOT_FOUND.getStatusCode();
        final String expectedMessage = "EndEntityProfileNotFoundException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new EndEntityProfileNotFoundException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnRoleNotFoundException() throws Exception {
        // given
        final long expectedCode = Status.NOT_FOUND.getStatusCode();
        final String expectedMessage = "RoleNotFoundException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new RoleNotFoundException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 409
    @Test
    public void shouldFormProperErrorResponseOnAdminAlreadyApprovedRequestException() throws Exception {
        // given
        final long expectedCode = Status.CONFLICT.getStatusCode();
        final String expectedMessage = "AdminAlreadyApprovedRequestException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new AdminAlreadyApprovedRequestException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 413
    @Test
    public void shouldFormProperErrorResponseOnStreamSizeLimitExceededException() throws Exception {
        // given
        final long expectedCode = 413;
        final String expectedMessage = "StreamSizeLimitExceededException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new StreamSizeLimitExceededException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    // 422
    @Test
    public void shouldFormProperErrorResponseOnEndEntityProfileValidationException() throws Exception {
        // given
        final long expectedCode = 422;
        final String expectedMessage = "EndEntityProfileValidationException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new EndEntityProfileValidationException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnUserDoesntFullfillEndEntityProfile() throws Exception {
        // given
        final long expectedCode = 422;
        final String expectedMessage = "UserDoesntFullfillEndEntityProfile error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new UserDoesntFullfillEndEntityProfile(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnCertificateExtensionException() throws Exception {
        // given
        final long expectedCode = 422;
        final String expectedMessage = "CertificateExtensionException error message";
        expect(dummyMock.throwException(anyInt())).andThrow(new CertificateExtensionException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }

    @Test
    public void shouldFormProperErrorResponseOnCertificateEncodingException() throws Exception {
        // given
        final long expectedCode = Status.INTERNAL_SERVER_ERROR.getStatusCode();
        final String expectedMessage = ExceptionHandler.DEFAULT_ERROR_MESSAGE;
        expect(dummyMock.throwException(anyInt())).andThrow(new CertificateEncodingException(expectedMessage));
        replay(dummyMock);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/dummy").get();
        final int actualHttpStatus = actualResponse.getStatus();
        final String actualJson = actualResponse.getEntity(String.class);
        // then
        assertJsonContentType(actualResponse);
        assertEquals(expectedCode, actualHttpStatus);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJson);
        verify(dummyMock);
    }
}
