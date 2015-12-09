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
package org.cesecore.keys.token.p11.exception;

/**
 * Classes in this packages throws this exception when an unexpected problem
 * occurs that should not occur at any circumstances.
 * @version $Id$
 *
 */
public class P11RuntimeException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public P11RuntimeException(final String message, final Exception cause) {
        super( message, cause );
    }
}
