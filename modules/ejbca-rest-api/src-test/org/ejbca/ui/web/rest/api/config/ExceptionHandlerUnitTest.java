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
package org.ejbca.ui.web.rest.api.config;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.*;
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
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.*;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.*;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.types.ExceptionInfoType;
import org.junit.Test;

import javax.ws.rs.core.Response;

import static javax.ws.rs.core.Response.Status;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * A unit test class for ExceptionHandler to test correctness of mapping between Exception and Error response.
 *
 * @version $Id: ExceptionHandler.java 28962 2018-05-21 06:54:45Z andrey_s_helmes $
 */
public class ExceptionHandlerUnitTest {

    private ExceptionHandler testClass = new ExceptionHandler();

    // -----------------------------------------------------------------------------------------------------------------
    // EjbcaException
    // -----------------------------------------------------------------------------------------------------------------
    @Test
    public void shouldProperlyHandleApprovalException() {
        // given
        final int expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "This is ApprovalException.";
        final ApprovalException approvalException = new ApprovalException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(approvalException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleKeyStoreGeneralRaException() {
        // given
        final int expectedCode = Status.BAD_REQUEST.getStatusCode();
        final Exception exception = new Exception("This is KeyStoreGeneralRaException.");
        final String expectedMessage = exception.toString();
        final KeyStoreGeneralRaException keyStoreGeneralRaException = new KeyStoreGeneralRaException(exception);
        // when
        final Response actualResponse = testClass.toResponse(keyStoreGeneralRaException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleAuthLoginException() {
        // given
        final int expectedCode = Status.FORBIDDEN.getStatusCode();
        final String expectedMessage = "This is AuthLoginException.";
        final AuthLoginException authLoginException = new AuthLoginException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(authLoginException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleAuthStatusException() {
        // given
        final int expectedCode = Status.FORBIDDEN.getStatusCode();
        final String expectedMessage = "This is AuthStatusException.";
        final AuthStatusException authStatusException = new AuthStatusException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(authStatusException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleNotFoundException() {
        // given
        final int expectedCode = Status.NOT_FOUND.getStatusCode();
        final String expectedMessage = "This is NotFoundException.";
        final NotFoundException notFoundException = new NotFoundException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(notFoundException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleAlreadyRevokedException() {
        // given
        final int expectedCode = Status.CONFLICT.getStatusCode();
        final String expectedMessage = "This is AlreadyRevokedException.";
        final AlreadyRevokedException alreadyRevokedException = new AlreadyRevokedException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(alreadyRevokedException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleCustomFieldException() {
        // given
        final int expectedCode = 422;
        final String expectedMessage = "This is CustomFieldException.";
        final CustomFieldException customFieldException = new CustomFieldException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(customFieldException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleEndEntityProfileValidationRaException() {
        // given
        final int expectedCode = 422;
        final EndEntityProfileValidationException endEntityProfileValidationException = new EndEntityProfileValidationException("This is EndEntityProfileValidationRaException.");
        final String expectedMessage = endEntityProfileValidationException.toString();
        final EndEntityProfileValidationRaException endEntityProfileValidationRaException = new EndEntityProfileValidationRaException(endEntityProfileValidationException);
        // when
        final Response actualResponse = testClass.toResponse(endEntityProfileValidationRaException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleRevokeBackDateNotAllowedForProfileException() {
        // given
        final int expectedCode = 422;
        final String expectedMessage = "This is RevokeBackDateNotAllowedForProfileException.";
        final RevokeBackDateNotAllowedForProfileException revokeBackDateNotAllowedForProfileException = new RevokeBackDateNotAllowedForProfileException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(revokeBackDateNotAllowedForProfileException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    // -----------------------------------------------------------------------------------------------------------------
    // CesecoreException
    // -----------------------------------------------------------------------------------------------------------------
    @Test
    public void shouldProperlyHandleCertificateRevokeException() {
        // given
        final int expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "This is CertificateRevokeException.";
        final CertificateRevokeException certificateRevokeException = new CertificateRevokeException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(certificateRevokeException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleCertificateSerialNumberException() {
        // given
        final int expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "This is CertificateSerialNumberException.";
        final CertificateSerialNumberException certificateSerialNumberException = new CertificateSerialNumberException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(certificateSerialNumberException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleEndEntityExistsException() {
        // given
        final int expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "This is EndEntityExistsException.";
        final EndEntityExistsException endEntityExistsException = new EndEntityExistsException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(endEntityExistsException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleCADoesntExistsException() {
        // given
        final int expectedCode = Status.NOT_FOUND.getStatusCode();
        final String expectedMessage = "This is CADoesntExistsException.";
        final CADoesntExistsException cADoesntExistsException = new CADoesntExistsException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(cADoesntExistsException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleCertificateProfileDoesNotExistException() {
        // given
        final int expectedCode = Status.NOT_FOUND.getStatusCode();
        final String expectedMessage = "This is CertificateProfileDoesNotExistException.";
        final CertificateProfileDoesNotExistException certificateProfileDoesNotExistException = new CertificateProfileDoesNotExistException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(certificateProfileDoesNotExistException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleNoSuchEndEntityException() {
        // given
        final int expectedCode = Status.NOT_FOUND.getStatusCode();
        final String expectedMessage = "This is NoSuchEndEntityException.";
        final NoSuchEndEntityException noSuchEndEntityException = new NoSuchEndEntityException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(noSuchEndEntityException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleIllegalNameException() {
        // given
        final int expectedCode = 422;
        final String expectedMessage = "This is IllegalNameException.";
        final IllegalNameException illegalNameException = new IllegalNameException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(illegalNameException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleIllegalValidityException() {
        // given
        final int expectedCode = 422;
        final String expectedMessage = "This is IllegalValidityException.";
        final IllegalValidityException illegalValidityException = new IllegalValidityException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(illegalValidityException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleInvalidAlgorithmException() {
        // given
        final int expectedCode = 422;
        final String expectedMessage = "This is InvalidAlgorithmException.";
        final InvalidAlgorithmException invalidAlgorithmException = new InvalidAlgorithmException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(invalidAlgorithmException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleCertificateCreateException() {
        // given
        final int expectedCode = Status.INTERNAL_SERVER_ERROR.getStatusCode();
        final String expectedMessage = ExceptionHandler.DEFAULT_ERROR_MESSAGE;
        final CertificateCreateException certificateCreateException = new CertificateCreateException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(certificateCreateException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleCAOfflineException() {
        // given
        final int expectedCode = Status.SERVICE_UNAVAILABLE.getStatusCode();
        final String expectedMessage = "This is CAOfflineException.";
        final CAOfflineException cAOfflineException = new CAOfflineException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(cAOfflineException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleCryptoTokenOfflineException() {
        // given
        final int expectedCode = Status.SERVICE_UNAVAILABLE.getStatusCode();
        final String expectedMessage = "This is CryptoTokenOfflineException.";
        final CryptoTokenOfflineException cryptoTokenOfflineException = new CryptoTokenOfflineException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(cryptoTokenOfflineException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleCTLogException() {
        // given
        final int expectedCode = Status.SERVICE_UNAVAILABLE.getStatusCode();
        final String expectedMessage = "This is CTLogException.";
        final CTLogException cTLogException = new CTLogException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(cTLogException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Standalone Exception <T extends Exception>
    // -----------------------------------------------------------------------------------------------------------------
    @Test
    public void shouldProperlyHandleWaitingForApprovalException() {
        // given
        final int expectedCode = Status.ACCEPTED.getStatusCode();
        final String expectedMessage = "This is WaitingForApprovalException.";
        final WaitingForApprovalException waitingForApprovalException = new WaitingForApprovalException(expectedMessage, 121);
        // when
        final Response actualResponse = testClass.toResponse(waitingForApprovalException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleApprovalRequestExecutionException() {
        // given
        final int expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "This is ApprovalRequestExecutionException.";
        final ApprovalRequestExecutionException approvalRequestExecutionException = new ApprovalRequestExecutionException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(approvalRequestExecutionException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleApprovalRequestExpiredException() {
        // given
        final int expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "This is ApprovalRequestExpiredException.";
        final ApprovalRequestExpiredException approvalRequestExpiredException = new ApprovalRequestExpiredException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(approvalRequestExpiredException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleRoleExistsException() {
        // given
        final int expectedCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedMessage = "This is RoleExistsException.";
        final RoleExistsException roleExistsException = new RoleExistsException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(roleExistsException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleAuthenticationFailedException() {
        // given
        final int expectedCode = Status.FORBIDDEN.getStatusCode();
        final String expectedMessage = "This is AuthenticationFailedException.";
        final AuthenticationFailedException authenticationFailedException = new AuthenticationFailedException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(authenticationFailedException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleAuthorizationDeniedException() {
        // given
        final int expectedCode = Status.FORBIDDEN.getStatusCode();
        final String expectedMessage = "This is AuthorizationDeniedException.";
        final AuthorizationDeniedException authorizationDeniedException = new AuthorizationDeniedException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(authorizationDeniedException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleEndEntityProfileNotFoundException() {
        // given
        final int expectedCode = Status.NOT_FOUND.getStatusCode();
        final String expectedMessage = "This is EndEntityProfileNotFoundException.";
        final EndEntityProfileNotFoundException endEntityProfileNotFoundException = new EndEntityProfileNotFoundException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(endEntityProfileNotFoundException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleRoleNotFoundException() {
        // given
        final int expectedCode = Status.NOT_FOUND.getStatusCode();
        final String expectedMessage = "This is RoleNotFoundException.";
        final RoleNotFoundException roleNotFoundException = new RoleNotFoundException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(roleNotFoundException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleAdminAlreadyApprovedRequestException() {
        // given
        final int expectedCode = Status.CONFLICT.getStatusCode();
        final String expectedMessage = "This is AdminAlreadyApprovedRequestException.";
        final AdminAlreadyApprovedRequestException adminAlreadyApprovedRequestException = new AdminAlreadyApprovedRequestException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(adminAlreadyApprovedRequestException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleStreamSizeLimitExceededException() {
        // given
        final int expectedCode = 413;
        final String expectedMessage = "This is StreamSizeLimitExceededException.";
        final StreamSizeLimitExceededException streamSizeLimitExceededException = new StreamSizeLimitExceededException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(streamSizeLimitExceededException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleEndEntityProfileValidationException() {
        // given
        final int expectedCode = 422;
        final String expectedMessage = "This is EndEntityProfileValidationException.";
        final EndEntityProfileValidationException endEntityProfileValidationException = new EndEntityProfileValidationException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(endEntityProfileValidationException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleUserDoesntFullfillEndEntityProfile() {
        // given
        final int expectedCode = 422;
        final String expectedMessage = "This is UserDoesntFullfillEndEntityProfile.";
        final UserDoesntFullfillEndEntityProfile userDoesntFullfillEndEntityProfile = new UserDoesntFullfillEndEntityProfile(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(userDoesntFullfillEndEntityProfile);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    @Test
    public void shouldProperlyHandleCertificateExtensionException() {
        // given
        final int expectedCode = 422;
        final String expectedMessage = "This is CertificateExtensionException.";
        final CertificateExtensionException certificateExtensionException = new CertificateExtensionException(expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(certificateExtensionException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    // -----------------------------------------------------------------------------------------------------------------
    // RestException
    // -----------------------------------------------------------------------------------------------------------------
    @Test
    public void shouldProperlyHandleRestException() {
        // given
        final int expectedCode = Status.NOT_ACCEPTABLE.getStatusCode();
        final String expectedMessage = "This is RestException.";
        final RestException restException = new RestException(expectedCode, expectedMessage);
        // when
        final Response actualResponse = testClass.toResponse(restException);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Exception
    // -----------------------------------------------------------------------------------------------------------------
    @Test
    public void shouldProperlyHandleException() {
        // given
        final int expectedCode = ExceptionHandler.DEFAULT_ERROR_CODE;
        final String expectedMessage = ExceptionHandler.DEFAULT_ERROR_MESSAGE;
        final Exception exception = new Exception("Strange exception.");
        // when
        final Response actualResponse = testClass.toResponse(exception);
        final ExceptionInfoType actualExceptionInfoType = (ExceptionInfoType) actualResponse.getEntity();
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertNotNull(actualExceptionInfoType);
        assertEquals(expectedCode, actualExceptionInfoType.getErrorCode());
        assertEquals(expectedMessage, actualExceptionInfoType.getErrorMessage());
    }
}
