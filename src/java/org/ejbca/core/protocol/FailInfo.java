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
 * $Header: /home/tomas/Dev/cvs2svn/ejbca-cvsbackup/ejbca/src/java/org/ejbca/core/protocol/FailInfo.java,v 1.1 2006-01-17 20:28:06 anatom Exp $
 * $Revision: 1.1 $
 * $Date: 2006-01-17 20:28:06 $
 *
 */
package org.ejbca.core.protocol;

import java.io.Serializable;

/**
 * Encapsulates the possible values for the failinfo part of a SCEP FAILURE response.
 *
 * @author Jon Barber (jon.barber@acm.org)
 */

public class FailInfo implements Serializable {

    /**
     * Unrecognized or unsupported algorithm ident
     */
    public static final FailInfo BAD_ALGORITHM = new FailInfo(0);

    /**
     * Integrity check failed
     */
    public static final FailInfo BAD_MESSAGE_CHECK = new FailInfo(1);

    /**
     * Transaction not permitted or supported
     */
    public static final FailInfo BAD_REQUEST = new FailInfo(2);


    /**
     * Message time field was not sufficiently close to the system time
     */
    public static final FailInfo BAD_TIME = new FailInfo(3);

    /**
     * No certificate could be identified matching the provided criteria
     */
    public static final FailInfo BAD_CERTIFICATE_ID = new FailInfo(4);
    /**
     * The value actually encoded into the response message as the failinfo attribute
     */
    private final int value;

    private FailInfo(int value) {
        this.value = value;
    }

    /**
     * Gets the value embedded in the response message as a failinfo attribute
     * @return  the value to use
     */
    public String getValue() {
        return Integer.toString(value);
    }


    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FailInfo)) return false;

        final FailInfo scepResponseStatus = (FailInfo) o;

        if (value != scepResponseStatus.value) return false;

        return true;
    }

    public int hashCode() {
        return value;
    }
}
