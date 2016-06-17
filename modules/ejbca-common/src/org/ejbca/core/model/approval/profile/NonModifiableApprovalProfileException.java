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
 * Thrown to show that somebody has tried to add steps or partitions to a profile which is set to be unmodifiable. Should not happen other than due
 * to programmer error, so is a RuntimeException
 * 
 * @version $Id$
 *
 */
public class NonModifiableApprovalProfileException extends RuntimeException{

    private static final long serialVersionUID = 1L;

    public NonModifiableApprovalProfileException() {
        super();
    }

    public NonModifiableApprovalProfileException(String message, Throwable cause) {
        super(message, cause);
    }

    public NonModifiableApprovalProfileException(String message) {
        super(message);
    }

    public NonModifiableApprovalProfileException(Throwable cause) {
        super(cause);
    }



}
