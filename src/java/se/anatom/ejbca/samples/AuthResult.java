
package se.anatom.ejbca.samples;

import java.util.Hashtable;

/**
 * Class containing the complete result from
 * an authenticateUser request.
 *
 * @author Original code by Peter Neemeth
 * @version $Id: AuthResult.java,v 1.2 2002-10-24 20:10:51 herrvendil Exp $
 *
 */
public class AuthResult {
    
    /**
     * Constants for grant and reject
     */
    private static final boolean GRANT_STATUS = true;
    private static final boolean REJECT_STATUS = false;
    /**
     * Default to rejecting a request
     */
    private boolean status = REJECT_STATUS; //GRANT_STATUS or REJECT_STATUS
    /**
     * What was the reason to reject this request?
     */
    private String reason = ""; //No reason
    /**
     * This Hashtable keeps all the name-value pairs
     * in the result.
     */
    private Hashtable resultHash = new Hashtable();
    
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
     * @return reason for rejecting this request
     */
    public String getReason() { 
        return reason; 
    }
    /**
     * Get result as Hashtable.
     */
    public Hashtable getResult() {
        return resultHash;
    }
   /** Set status to GRANT 
     */
    public void grant() {
        status = GRANT_STATUS;
    }
    /**
     * @return true if the request was GRANTed
     */
    public boolean granted() {
        return status == GRANT_STATUS;
    }
    /** Set status to REJECT */
    public void reject() {
        status = REJECT_STATUS;
    }
    /**
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
