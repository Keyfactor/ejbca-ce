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
package org.ejbca.ui.web.rest.api.exception;

import org.ejbca.ui.web.rest.api.io.response.ExceptionErrorRestResponse;

import javax.validation.ConstraintViolationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

@Provider
public class ValidationExceptionMapper implements ExceptionMapper<ConstraintViolationException> {

    @Override
    public Response toResponse(ConstraintViolationException arg0) {

        ExceptionErrorRestResponse exceptionErrorRestResponse = ExceptionErrorRestResponse.builder()
                .errorCode(Response.Status.BAD_REQUEST.getStatusCode())
                .errorMessage(arg0.getConstraintViolations().iterator().next().getMessage())
                .build();

        return Response
                .status(Response.Status.BAD_REQUEST.getStatusCode())
                .entity(exceptionErrorRestResponse)
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

}
