/**
 * $Header: /home/tomas/Dev/cvs2svn/ejbca-cvsbackup/ejbca/src/java/se/anatom/ejbca/protocol/FailInfo.java,v 1.2 2003-10-11 08:03:27 anatom Exp $
 * $Revision: 1.2 $
 * $Date: 2003-10-11 08:03:27 $
 *
 */
package se.anatom.ejbca.protocol;

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
