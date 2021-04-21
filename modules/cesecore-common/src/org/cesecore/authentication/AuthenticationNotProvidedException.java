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
package org.cesecore.authentication;

import java.io.Serializable;

/**
 * Thrown whenever a public session bean is entered without any authentication token at all
 * (i.e. no login attempted).
 */
public class AuthenticationNotProvidedException extends AuthenticationFailedException implements Serializable {

    private static final long serialVersionUID = 1;

    public AuthenticationNotProvidedException() {
        super();
    }

    public AuthenticationNotProvidedException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public AuthenticationNotProvidedException(final String message) {
        super(message);
    }

    public AuthenticationNotProvidedException(final Throwable cause) {
        super(cause);
    }
}
