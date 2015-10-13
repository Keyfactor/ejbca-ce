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
package org.ejbca.core.ejb.upgrade;

import javax.ejb.ApplicationException;

/**
 * Thrown in case an upgrade routine fails. Should trigger rollback. 
 * 
 * @version $Id$
 *
 */
@ApplicationException(rollback = true)
public class UpgradeFailedException extends Exception {

    private static final long serialVersionUID = -8607042944389555117L;

    /**
     * 
     */
    public UpgradeFailedException() {
    }

    /**
     * @param message
     */
    public UpgradeFailedException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public UpgradeFailedException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public UpgradeFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public UpgradeFailedException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
