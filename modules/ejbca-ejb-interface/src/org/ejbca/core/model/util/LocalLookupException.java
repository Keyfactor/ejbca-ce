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
package org.ejbca.core.model.util;

/**
 * Thrown in case a local lookup fails
 * 
 * @version $Id$
 *
 */
public class LocalLookupException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public LocalLookupException() {
        super();
    }

    public LocalLookupException(String message, Throwable cause) {
        super(message, cause);
    }

    public LocalLookupException(String message) {
        super(message);
    }

    public LocalLookupException(Throwable cause) {
        super(cause);
    }


}
