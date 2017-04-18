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
package org.ejbca.util.query;

import java.io.Serializable;

import org.apache.commons.lang.StringEscapeUtils;

/**
 * A base class used by Query class to build a query. Inherited by UserMatch, TimeMatch and
 * LogMatch. Main function is getQueryString which is abstract and must be overloaded.
 *
 * @version $Id$
 */
public abstract class BasicMatch implements Serializable {
    
    private static final long serialVersionUID = -1L;

    public static final int MATCH_TYPE_EQUALS = 0;
    public static final int MATCH_TYPE_BEGINSWITH = 1;
    public static final int MATCH_TYPE_CONTAINS = 2;

    /** Creates a new instance of BasicMatch */
    public BasicMatch() { }

    /** @return a SQL statement fragment from the given data (with escaped single quotes). */
    public abstract String getQueryString();

    /** @return true if query is legal, false otherwise */
    public abstract boolean isLegalQuery();

    /** Escape single quotes as double quotes */
    public String escapeSql(final String matchValue) {
        return StringEscapeUtils.escapeSql(matchValue);
    }
}
