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
package org.ejbca.core.model.approval.profile;

/**
 * @version $Id$
 *
 */
public class NoSuchApprovalStepException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * 
     */
    public NoSuchApprovalStepException() {
    }

    /**
     * @param message
     */
    public NoSuchApprovalStepException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public NoSuchApprovalStepException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public NoSuchApprovalStepException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public NoSuchApprovalStepException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
