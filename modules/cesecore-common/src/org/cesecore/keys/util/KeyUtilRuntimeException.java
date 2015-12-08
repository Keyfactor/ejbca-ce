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
package org.cesecore.keys.util;

/**
 * Exception thrown by classes in this package when an error occur that
 * should not be handled.
 * @version $Id$
 *
 */
public class KeyUtilRuntimeException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    KeyUtilRuntimeException( final String message, final Exception cause ) {
        super(message, cause);
    }

    KeyUtilRuntimeException( final String message ) {
        super(message);
    }
}
