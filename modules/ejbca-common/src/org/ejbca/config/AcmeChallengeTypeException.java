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
package org.ejbca.config;

/**
 * Thrown if invalid challenge types were encountered when constructing an ACME alias.
 */
public class AcmeChallengeTypeException extends Exception {

    private static final long serialVersionUID = 1L;

    public AcmeChallengeTypeException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public AcmeChallengeTypeException(String message, Throwable cause) {
        super(message, cause);
    }

    public AcmeChallengeTypeException(String message) {
        super(message);
    }

    public AcmeChallengeTypeException(Throwable cause) {
        super(cause);
    }

}
