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

/**
 * Thrown to show that the administrator performing an approval was the same as the one originally requesting the action. 
 * 
 * @version $Id$
 *
 */
public class SelfApprovalException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * 
     */
    public SelfApprovalException() {
    }

    /**
     * @param message
     */
    public SelfApprovalException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public SelfApprovalException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public SelfApprovalException(String message, Throwable cause) {
        super(message, cause);
    }

}
