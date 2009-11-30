/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import org.ejbca.core.model.approval.ApprovalException;

/**
 * Base for all specific application exceptions thrown by EJBCA. Can be used to catch any
 * non-crititcal application exceptions thay may be possible to handle: <code> try { . . . } catch
 * (EjbcaException e) { error("Error: blahblah", e); ... }</code>
 *
 * @version $Id$
 */
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
        processException(exception);
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

    /** This method check the potential error code nested in the exception in order to set the error code.
     * @param exception the exception to process.
     */
    private void processException(Exception exception) {
        // check if the exception is an instance of ApprovalException.
        if (exception != null && exception instanceof ApprovalException) {
            ApprovalException approvalException = (ApprovalException) exception;
            this.errorCode = approvalException.getErrorCode();
        }
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