/*
 * BasicMatch.java
 *
 * Created on den 20 juli 2002, 23:20
 */
package se.anatom.ejbca.util.query;

/**
 * A base class used by Query class to build a query. Inherited by UserMatch, TimeMatch and
 * LogMatch. Main function is getQueryString which is abstract and must be overloaded.
 *
 * @author tomselleck
 *
 * @see se.anatom.ejbca.util.query.UserMatch
 * @see se.anatom.ejbca.util.query.TimeMatch
 * @see se.anatom.ejbca.util.query.LogMatch
 */
public abstract class BasicMatch implements java.io.Serializable {
    // Public Constants
    public static final int MATCH_TYPE_EQUALS = 0;
    public static final int MATCH_TYPE_BEGINSWITH = 1;
    public static final int MATCH_TYPE_CONTAINS = 2;

    /**
     * Creates a new instance of BasicMatch
     */
    public BasicMatch() {
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getQueryString();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract boolean isLegalQuery();
}
