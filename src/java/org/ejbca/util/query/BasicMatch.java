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
 
/*
 * BasicMatch.java
 *
 * Created on den 20 juli 2002, 23:20
 */
package org.ejbca.util.query;

/**
 * A base class used by Query class to build a query. Inherited by UserMatch, TimeMatch and
 * LogMatch. Main function is getQueryString which is abstract and must be overloaded.
 *
 * @version $Id$
 *
 * @see org.ejbca.util.query.UserMatch
 * @see org.ejbca.util.query.TimeMatch
 * @see org.ejbca.util.query.LogMatch
 */
public abstract class BasicMatch implements java.io.Serializable {
	
	private static final long serialVersionUID = -1L;
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
