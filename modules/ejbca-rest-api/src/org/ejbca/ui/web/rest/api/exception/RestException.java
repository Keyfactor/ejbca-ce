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

/**
 * A general exception of REST API containing error code, error message and optionally the cause.
 * <br/>
 * <ul>
 *     <li>The error code should match HTTP status codes;</li>
 *     <li>The error message SHOULD NOT contain any sensitive information, as this message is forwarded to API end client;</li>
 *     <li>The cause might be forwarded for the logging purpose.</li>
 * </ul>
 *
 * @version $Id: RestException.java 28962 2018-05-21 06:54:45Z andrey_s_helmes $
 */
public class RestException extends Exception {
    private static final long serialVersionUID = 1L;
    private final int errorCode;

    /**
     * Simple constructor.
     *
     * @param errorCode error code matching HTTP status codes.
     * @param errorMessage error message.
     */
    public RestException(final int errorCode, final String errorMessage) {
        super(errorMessage);
        this.errorCode = errorCode;
    }

    /**
     * Full constructor.
     *
     * @param errorCode error code matching HTTP status codes.
     * @param errorMessage error message.
     * @param cause the cause.
     */
    public RestException(final int errorCode, final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
        this.errorCode = errorCode;
    }

    /**
     * Returns the error code.
     *
     * @return error code.
     */
    public int getErrorCode() {
        return errorCode;
    }
}
