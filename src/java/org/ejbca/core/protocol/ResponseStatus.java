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
 
/**
 * $Header: /home/tomas/Dev/cvs2svn/ejbca-cvsbackup/ejbca/src/java/org/ejbca/core/protocol/ResponseStatus.java,v 1.1 2006-01-17 20:28:06 anatom Exp $
 * $Revision: 1.1 $
 * $Date: 2006-01-17 20:28:06 $
 *
 */
package org.ejbca.core.protocol;

import java.io.Serializable;

/**
 * Encapsulates the possible values for the status of a SCEP response.
 *
 * @author Jon Barber (jon.barber@acm.org)
 */

public class ResponseStatus implements Serializable {

    /**
     * Request granted
     */
    public static final ResponseStatus SUCCESS = new ResponseStatus(0);

    /**
     * Request rejected
     */
    public static final ResponseStatus FAILURE = new ResponseStatus(2);

    /**
     * Request pending for approval
     */
    public static final ResponseStatus PENDING = new ResponseStatus(3);

    /**
     * The value actually encoded into the response message as a pkiStatus attribute
     */
    private final int value;

    private ResponseStatus(int value) {
        this.value = value;
    }

    /**
     * Gets the value embedded in the response message as a pkiStatus attribute
     * @return  the value to use
     */
    public String getValue() {
        return Integer.toString(value);
    }


    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ResponseStatus)) return false;

        final ResponseStatus scepResponseStatus = (ResponseStatus) o;

        if (value != scepResponseStatus.value) return false;

        return true;
    }

    public int hashCode() {
        return value;
    }
}
