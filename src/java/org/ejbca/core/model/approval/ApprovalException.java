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
package org.ejbca.core.model.approval;

import org.ejbca.core.ErrorCode;

/**
 * General Exception when something serious goes wrong when
 * managing approvals
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class ApprovalException extends Exception {

    private static final long serialVersionUID = 7232454568592982535L;

    /** Error code associated to this exception. */
    private ErrorCode errorCode = ErrorCode.NOT_SPECIFIED;

    /** Constructor.
     * @param message Human redable error message, can not be NULL.
     * @param cause exception to be embedded.
     */
	public ApprovalException(String message, Throwable cause) {
		super(message, cause);
	}

    /** Constructor.
     * @param message Human redable error message, can not be NULL.
     */
	public ApprovalException(String message) {
		super(message);
	}

    /** Constructor.
     * @param errorCode associated error code.
     * @param message Human redable error message, can not be NULL.
     * @param cause exception to be embedded.
     */
	public ApprovalException(ErrorCode errorCode, String message, Throwable cause) {
		super(message, cause);
        this.errorCode = errorCode;
	}

    /** Constructor.
     * @param errorCode associated error code.
     * @param message Human redable error message, can not be NULL.
     */
	public ApprovalException(ErrorCode errorCode, String message) {
		super(message);
        this.errorCode = errorCode;
	}

    /** Get error code.
     * @return error code.
     */
    public ErrorCode getErrorCode() {
        return errorCode;
    }

    /** Set error code.
     * @param errorCode the error code to set.
     */
    public void setErrorCode(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }
}