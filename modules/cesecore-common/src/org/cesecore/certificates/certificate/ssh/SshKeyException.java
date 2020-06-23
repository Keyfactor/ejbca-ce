/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate.ssh;

import javax.xml.ws.WebFault;

/**
 * Thrown to mark any unresolvable issues with SSH keys.
 * 
 * @version $Id$
 *
 */
@WebFault
public class SshKeyException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * 
     */
    public SshKeyException() {
    }

    /**
     * @param message
     */
    public SshKeyException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public SshKeyException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public SshKeyException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public SshKeyException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
