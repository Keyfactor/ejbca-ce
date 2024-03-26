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

import javax.ejb.EJBException;
import javax.el.ELException;
import javax.faces.FacesException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.apache.log4j.Logger;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.ui.web.rest.api.exception.CesecoreExceptionClasses;
import org.ejbca.ui.web.rest.api.exception.EjbcaExceptionClasses;
import org.ejbca.ui.web.rest.api.exception.ExceptionClasses;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.ExceptionErrorRestResponse;
import org.ejbca.ui.web.rest.api.io.response.ExceptionInfoRestResponse;
import org.ejbca.ui.web.rest.api.io.response.ExceptionInfoRestResponse.ExceptionInfoRestResponseBuilder;

import com.keyfactor.CesecoreException;

import java.lang.reflect.InvocationTargetException;

/**
 * General JAX-RS Exception handler to catch an Exception and create its appropriate response with error's status and error's message.
 */
@Provider
public class ExceptionHandler implements ExceptionMapper<Exception> {

    private static final Logger logger = Logger.getLogger(ExceptionHandler.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    public static final int DEFAULT_ERROR_CODE = Status.INTERNAL_SERVER_ERROR.getStatusCode();
    public static final String DEFAULT_ERROR_MESSAGE = "General failure.";

    @Context
    HttpServletRequest requestContext;
    
    @Override
    public Response toResponse(Exception rootException) {
        Throwable exception = unwrap(rootException);

        ExceptionErrorRestResponse exceptionErrorRestResponse = null;
        if (logger.isTraceEnabled()) {
            logger.trace("toResponse(" + exception.getClass().getName() + " exception)");
        }
        // Map through EjbcaException
        if (exception instanceof EjbcaException) {
            exceptionErrorRestResponse = mapEjbcaException((EjbcaException) exception);
        }
        // Map through CesecoreException
        else if (exception instanceof CesecoreException) {
            exceptionErrorRestResponse = mapCesecoreException((CesecoreException) exception);
        }
        // Map managed exception
        else if (mapManagedException(exception) != null) {
            return getExceptionResponse(mapManagedException(exception));
        }
        // Map through WebApplicationException
        else if (exception instanceof WebApplicationException) {
            final WebApplicationException webApplicationException = (WebApplicationException) exception;
            // Forward server's exception
            exceptionErrorRestResponse = ExceptionErrorRestResponse.builder()
                    .errorCode(webApplicationException.getResponse().getStatus())
                    .errorMessage(webApplicationException.getMessage())
                    .build();
        }
        else if (exception instanceof RestException) {
            final RestException restException = (RestException) exception;
            exceptionErrorRestResponse = ExceptionErrorRestResponse.builder()
                    .errorCode(restException.getErrorCode())
                    .errorMessage(restException.getMessage())
                    .build();
        }
        // If previous mapping failed, try to map through Standalone Exception
        if (exceptionErrorRestResponse == null) {
            exceptionErrorRestResponse = mapException(exception);
        }
        // Fall back to default if mapping doesn't exist
        if (exceptionErrorRestResponse == null) {
            logger.warn("Cannot find a proper mapping for the exception, falling back to default.", exception);
            exceptionErrorRestResponse = ExceptionErrorRestResponse.builder()
                    .errorCode(DEFAULT_ERROR_CODE)
                    .errorMessage(DEFAULT_ERROR_MESSAGE)
                    .build();
        }
        return getExceptionResponse(exceptionErrorRestResponse);
    }

    private Throwable unwrap(Throwable throwable) {
        if (throwable instanceof InvocationTargetException) {
            throwable = ((InvocationTargetException) throwable).getTargetException();

            return unwrap(throwable);
        }

        if (isCauseWrapped(throwable)) {
            do {
                throwable = throwable.getCause();
            } while (isCauseWrapped(throwable));

            return unwrap(throwable);
        }

        return throwable;
    }

    private static boolean isCauseWrapped(Throwable throwable) {
        return throwable instanceof FacesException
                || throwable instanceof EJBException
                || throwable instanceof ELException
                || isRuntimeLoophole(throwable)
                ;
    }

    private static boolean isRuntimeLoophole(Throwable throwable) {
        // IllegalStateException & RuntimeException without a message are just wrappers
        return throwable != null &&
                (
                        (IllegalStateException.class.equals(throwable.getClass()) || RuntimeException.class.equals(throwable.getClass()))
                                && wasInitiatedWithoutMessage(throwable)
                );
    }

    private static boolean wasInitiatedWithoutMessage(Throwable throwable) {
        // throwable has no message or its cause has a generated message
        return throwable.getMessage() == null || throwable.getCause() != null &&
                (
                        throwable.getMessage().equals(throwable.getCause().toString())
                                || throwable.getMessage().equals(throwable.getCause().getMessage())
                );
    }

    // Map managed exceptions (not of error nature)
    private ExceptionInfoRestResponse mapManagedException(final Throwable exception) {
        switch (ExceptionClasses.fromClass(exception.getClass())) {
            // 202
            case WaitingForApprovalException:
                WaitingForApprovalException e = (WaitingForApprovalException) exception;
                ExceptionInfoRestResponseBuilder response = ExceptionInfoRestResponse.builder()
                    .statusCode(Status.ACCEPTED.getStatusCode())
                    .infoMessage(exception.getMessage());
                // Only link finalize for enrollment related requests
                if (!(e.getMessage().equals(intres.getLocalizedMessage("ra.approvalrevoke")) ||
                      e.getMessage().equals(intres.getLocalizedMessage("ra.approvalcaactivation")))) {
                    response.link(getRestBaseUrl() + e.getRequestId() + "/finalize");
                    
                }
                return response.build();
            default:
                return null;
        }
    }

    /**
     * Returns the REST API base URL including correct domain name and port
     * E.g. https://domainname:8443/ejbca/ejbca-rest-api/v1
     * @return Rest API base URL
     */
    private String getRestBaseUrl() {
        return requestContext.getRequestURL().substring(0, requestContext.getRequestURL().indexOf("/v")) + "/";
    }
    
    // Map EjbcaException extending exceptions
    private ExceptionErrorRestResponse mapEjbcaException(final EjbcaException ejbcaException) {
        switch (EjbcaExceptionClasses.fromClass(ejbcaException.getClass())) {
            // 400
            case ApprovalException:
            case KeyStoreGeneralRaException:
            case PublisherException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(Status.BAD_REQUEST.getStatusCode())
                        .errorMessage(ejbcaException.getMessage())
                        .build();
            // 403
            case AuthLoginException:
            case AuthStatusException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(Status.FORBIDDEN.getStatusCode())
                        .errorMessage(ejbcaException.getMessage())
                        .build();
            // 404
            case NotFoundException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(Status.NOT_FOUND.getStatusCode())
                        .errorMessage(ejbcaException.getMessage())
                        .build();
            // 409
            case AlreadyRevokedException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(Status.CONFLICT.getStatusCode())
                        .errorMessage(ejbcaException.getMessage())
                        .build();
            // 422
            // TODO These exception cannot be found in compilation classpath
//            case WrongTokenTypeException:
//            case CertificateProfileTypeNotAcceptedException:
            case CustomFieldException:
            case EndEntityProfileValidationRaException:
            case RevokeBackDateNotAllowedForProfileException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(422)
                        .errorMessage(ejbcaException.getMessage())
                        .build();
            default:
                return null;
        }
    }

    // Map CesecoreException extending exceptions
    private ExceptionErrorRestResponse mapCesecoreException(final CesecoreException cesecoreException) {
        switch (CesecoreExceptionClasses.fromClass(cesecoreException.getClass())) {
            // 400
            case CertificateRevokeException:
            case CertificateSerialNumberException:
            case EndEntityExistsException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(Status.BAD_REQUEST.getStatusCode())
                        .errorMessage(cesecoreException.getMessage())
                        .build();
            // 404
            case CADoesntExistsException:
            case CertificateProfileDoesNotExistException:
            case NoSuchEndEntityException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(Status.NOT_FOUND.getStatusCode())
                        .errorMessage(cesecoreException.getMessage())
                        .build();
            // 422
            case IllegalNameException:
            case IllegalValidityException:
            case InvalidAlgorithmException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(422)
                        .errorMessage(cesecoreException.getMessage())
                        .build();
            // 500
            case CertificateCreateException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(Status.INTERNAL_SERVER_ERROR.getStatusCode())
                        .errorMessage(DEFAULT_ERROR_MESSAGE)
                        .build();
            // 503
            case CryptoTokenOfflineException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(Status.SERVICE_UNAVAILABLE.getStatusCode())
                        .errorMessage("Device was unavailable.")
                        .build();
            case CAOfflineException:
            case CTLogException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(Status.SERVICE_UNAVAILABLE.getStatusCode())
                        .errorMessage(cesecoreException.getMessage())
                        .build();
            default:
                return null;
        }
    }

    private ExceptionErrorRestResponse mapException(final Throwable exception) {
        switch (ExceptionClasses.fromClass(exception.getClass())) {
            // 400
            case ApprovalRequestExecutionException:
            case ApprovalRequestExpiredException:
            case RoleExistsException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(Status.BAD_REQUEST.getStatusCode())
                        .errorMessage(exception.getMessage())
                        .build();
            // 403
            case AuthenticationFailedException:
            case AuthorizationDeniedException:
            case UnsupportedOperationException:
            case SelfApprovalException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(Status.FORBIDDEN.getStatusCode())
                        .errorMessage(exception.getMessage())
                        .build();
            // 404
            case EndEntityProfileNotFoundException:
            case RoleNotFoundException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(Status.NOT_FOUND.getStatusCode())
                        .errorMessage(exception.getMessage())
                        .build();
            // 409
            case AdminAlreadyApprovedRequestException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(Status.CONFLICT.getStatusCode())
                        .errorMessage(exception.getMessage())
                        .build();
            // 413
            case StreamSizeLimitExceededException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(413)
                        .errorMessage(exception.getMessage())
                        .build();
            // 422
            case EndEntityProfileValidationException:
            case UserDoesntFullfillEndEntityProfile:
            case CertificateExtensionException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(422)
                        .errorMessage(exception.getMessage())
                        .build();
            // 500
            case CertificateEncodingException:
                return ExceptionErrorRestResponse.builder()
                        .errorCode(DEFAULT_ERROR_CODE)
                        .errorMessage(DEFAULT_ERROR_MESSAGE)
                        .build();
            default:
                return null;
        }
    }

    private Response getExceptionResponse(final ExceptionErrorRestResponse exceptionInfoRestResponse) {
        return Response
                .status(exceptionInfoRestResponse.getErrorCode())
                .entity(exceptionInfoRestResponse)
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    private Response getExceptionResponse(final ExceptionInfoRestResponse exceptionInfoRestResponse) {
        return Response
                .status(exceptionInfoRestResponse.getStatusCode())
                .entity(exceptionInfoRestResponse)
                .type(MediaType.APPLICATION_JSON)
                .build();
    }
}
