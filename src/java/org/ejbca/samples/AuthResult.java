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
 
package org.ejbca.samples;

import java.util.HashMap;
import java.util.Map;


/**
 * Class containing the complete result from an authenticateUser request.
 *
 * @author Original code by Peter Neemeth
 * @version $Id$
 */
public class AuthResult {
    /** Constants for grant and reject */
    private static final boolean GRANT_STATUS = true;
    private static final boolean REJECT_STATUS = false;

    /** Default to rejecting a request */
    private boolean status = REJECT_STATUS; //GRANT_STATUS or REJECT_STATUS

    /** What was the reason to reject this request? */
    private String reason = ""; //No reason

    /** This map keeps all the name-value pairs in the result. */
    private Map<String, String> resultHash = new HashMap<String, String>();

    /**
     * Adds a new key, value pair to the grant response.
     *
     * @param key left hand value. Must be unique for this result
     * @param value right hand value
     */
    public void add(final String key, final String value) {
        resultHash.put(key, value);
    }

    /**
     * DOCUMENT ME!
     *
     * @return reason for rejecting this request
     */
    public String getReason() {
        return reason;
    }

    /**
     * Get result as Map.
     *
     * @return hash table of results
     */
    public Map<String, String> getResult() {
        return resultHash;
    }

    /**
     * Set status to GRANT
     */
    public void grant() {
        status = GRANT_STATUS;
    }

    /**
     * DOCUMENT ME!
     *
     * @return true if the request was GRANTed
     */
    public boolean granted() {
        return status == GRANT_STATUS;
    }

    /**
     * Set status to REJECT
     */
    public void reject() {
        status = REJECT_STATUS;
    }

    /**
     * DOCUMENT ME!
     *
     * @return true if the request was REJECTed
     */
    public boolean rejected() {
        return status == REJECT_STATUS;
    }

    /**
     * Set reason of rejected request. No default.
     *
     * @param newReason describing why the request was rejected
     */
    public void setReason(final String newReason) {
        reason = newReason;
    }
}
