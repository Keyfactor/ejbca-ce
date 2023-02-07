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
package org.ejbca.core.protocol.acme;

import javax.ws.rs.core.Response.Status;

import org.cesecore.NonSensitiveException;
import org.ejbca.core.protocol.acme.response.AcmeProblem;
import org.ejbca.core.protocol.acme.response.AcmeProblemResponse;

/**
 * Custom Exception for reporting problems from the ACME protocol.
 * 
 * @see AcmeProblemResponse
 */
@NonSensitiveException
public class AcmeProblemException extends Exception {

    private static final long serialVersionUID = 1L;

    private final int httpStatusCode;
    private final AcmeProblemResponse acmeProblemResponse;

    public AcmeProblemException(final Status httpStatus, final AcmeProblem acmeProblem, final String acmeProblemDetails) {
        this(httpStatus, new AcmeProblemResponse(acmeProblem, acmeProblemDetails));
    }

    public AcmeProblemException(final Status httpStatus, final AcmeProblem acmeProblem) {
        this(httpStatus, new AcmeProblemResponse(acmeProblem));
    }

    public AcmeProblemException(final Status httpStatus, final AcmeProblemResponse acmeProblemResponse) {
        this.httpStatusCode = httpStatus.getStatusCode();
        this.acmeProblemResponse = acmeProblemResponse;
    }

    public int getHttpStatusCode() { return httpStatusCode; }
    public AcmeProblemResponse getAcmeProblemResponse() { return acmeProblemResponse; }
}
