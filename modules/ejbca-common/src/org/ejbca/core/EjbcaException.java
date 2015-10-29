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
 
package org.ejbca.core;

import javax.xml.ws.WebFault;

import org.cesecore.ErrorCode;


/**
 * Base for all specific application exceptions thrown by EJBCA. Can be used to catch any
 * non-crititcal application exceptions they may be possible to handle: <code> try { . . . } catch
 * (EjbcaException e) { error("Error: blahblah", e); ... }</code>
 *
 * @version $Id$
 */
@WebFault
public class EjbcaException extends Exception {

    private static final long serialVersionUID = -3754146611270578813L;

    /** The error code describes the cause of the exception. */
    ErrorCode errorCode = null;

    /**
     * Constructor used to create exception without an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     */
    public EjbcaException() {
        super();
    }

    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public EjbcaException(String message) {
        super(message);
    }

    /**
     * Constructor used to create exception with an errorCode. Calls the same default constructor
     * in the base class <code>Exception</code>.
     *
     * @param errorCode defines the cause of the exception.
     */
    public EjbcaException(ErrorCode errorCode) {
        super();
        this.errorCode = errorCode;
    }

    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param errorCode defines the cause of the exception.
     * @param message Human redable error message, can not be NULL.
     */
    public EjbcaException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Constructor used to create exception with an embedded exception. Calls the same constructor
     * in baseclass <code>Exception</code>.
     *
     * @param exception exception to be embedded.
     */
    public EjbcaException(Exception exception) {
        super(exception);
        if (exception instanceof EjbcaException) {
        	errorCode = ((EjbcaException) exception).getErrorCode();
        }
    }

    /**
     * Constructor used to create exception with an embedded exception. Calls the same constructor
     * in baseclass <code>Exception</code>.
     *
     * @param errorCode defines the cause of the exception.
     * @param exception exception to be embedded.
     */
    public EjbcaException(ErrorCode errorCode, Exception exception) {
        super(exception);
        this.errorCode = errorCode;
    }

    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human readable error message, can not be NULL.
     */
    public EjbcaException(String message, Throwable cause) {
		super(message, cause);
        if (cause instanceof EjbcaException) {
        	errorCode = ((EjbcaException) cause).getErrorCode();
        }
	}

	public EjbcaException(ErrorCode errorCode, String message, Throwable cause) {
		super(message, cause);
        this.errorCode = errorCode;
	}

    /** Get the error code.
     * @return the error code.
     */
    public ErrorCode getErrorCode() {
        return errorCode;
    }

    /** Set the error code.
     * @param errorCode the error code.
     */
    public void setErrorCode(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }
}
