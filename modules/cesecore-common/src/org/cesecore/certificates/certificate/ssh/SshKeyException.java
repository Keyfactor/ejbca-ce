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
 */
@WebFault
public class SshKeyException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Constructor.
     */
    public SshKeyException() {
    }

    /**
     * Constructor.
     * @param message message.
     */
    public SshKeyException(String message) {
        super(message);
    }

    /**
     * Constructor.
     * @param cause cause.
     */
    public SshKeyException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructor.
     * @param message message.
     * @param cause cause.
     */
    public SshKeyException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructor.
     * @param message message.
     * @param cause cause.
     * @param enableSuppression enable suppression flag.
     * @param writableStackTrace writable stack trace flag.
     */
    public SshKeyException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
