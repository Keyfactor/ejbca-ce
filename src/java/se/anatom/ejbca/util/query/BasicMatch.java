/*
 * BasicMatch.java
 *
 * Created on den 20 juli 2002, 23:20
 */

package se.anatom.ejbca.util.query;

/**
 * A base class used by Query class to build a query. Inherited by UserMatch, TimeMatch and LogMatch.
 *
 * Main function is getQueryString which is abstract and must be overloaded.
 *
 * @see se.anatom.ejbca.util.query.UserMatch
 * @see se.anatom.ejbca.util.query.TimeMatch
 * @see se.anatom.ejbca.util.query.LogMatch
 * @author  tomselleck
 */
public abstract class BasicMatch implements java.io.Serializable {
    
    // Public Constants
    public final static int MATCH_TYPE_EQUALS      = 0;
    public final static int MATCH_TYPE_BEGINSWITH  = 1;
    
    /** Creates a new instance of BasicMatch */
    public BasicMatch() {
    }
    
    public abstract String getQueryString();
    
    public abstract boolean isLegalQuery();
}
