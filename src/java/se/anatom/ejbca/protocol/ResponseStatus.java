/**
 * $Header: /home/tomas/Dev/cvs2svn/ejbca-cvsbackup/ejbca/src/java/se/anatom/ejbca/protocol/ResponseStatus.java,v 1.2 2003-10-11 08:03:26 anatom Exp $
 * $Revision: 1.2 $
 * $Date: 2003-10-11 08:03:26 $
 *
 */
package se.anatom.ejbca.protocol;

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
