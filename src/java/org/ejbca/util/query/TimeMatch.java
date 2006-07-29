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
 
/*
 * TimeMatch.java
 *
 * Created on den 20 juli 2002, 23:20
 */
package org.ejbca.util.query;

import java.util.Date;


/**
 * A class used by Query class to build a query for ejbca log or ra modules. Inherits BasicMatch.
 * Main function is getQueryString which returns a fragment of SQL statment.
 *
 * @author TomSelleck
 * @version $Id: TimeMatch.java,v 1.2 2006-07-29 11:26:37 herrvendil Exp $
 *
 * @see org.ejbca.util.query.BasicMatch
 * @see org.ejbca.util.query.UserMatch
 * @see org.ejbca.util.query.LogMatch
 */
public class TimeMatch extends BasicMatch {
    // Public Constants
	/** UserMatch Specific Constant */	
    public static final int MATCH_WITH_TIMECREATED = 0;
    /** UserMatch Specific Constant */
    public static final int MATCH_WITH_TIMEMODIFIED = 1;
    
    /** ApprovalMatch Specific Constant */
    public static final int MATCH_WITH_REQUESTORAPPROVALTIME = 0;
    /** ApprovalMatch Specific Constant */
    public static final int MATCH_WITH_EXPIRETIME = 1;

    // Private Constants.
    private static final String[] MATCH_WITH_SQLNAMES = {
        "time", "time", "timeCreated", "timeModified","requestdate","expiredate"
    }; // Represents the column names in log/ra tables.

    // Public methods.

    /**
     * Creates a new instance of TimeMatch. Construtor should only be used in ra user queries.
     *
     * @param type uses Query class constants to determine if it's a log query or ra query.
     * @param matchwith should be one of MATCH_WITH contants to determine with field to search.
     *        Only used in ra user queries.
     * @param startdate gives a startdate for the query, null if not needed.
     * @param startdate gives a enddate for the query, null if not needed.
     */
    public TimeMatch(int type, int matchwith, Date startdate, Date enddate) {
        this.type = type;
        this.matchwith = matchwith;
        this.startdate = startdate;
        this.enddate = enddate;
    }

    /**
     * Creates a new instance of TimeMatch. Constructor should only be used in log queries.
     *
     * @param type uses Query class constants to determine if it's a log query or ra query.
     * @param startdate gives a startdate for the query, null if not needed.
     * @param startdate gives a enddate for the query, null if not needed.
     */
    public TimeMatch(int type, Date startdate, Date enddate) {
        this.type = type;
        this.matchwith = 0;
        this.startdate = startdate;
        this.enddate = enddate;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getQueryString() {
        String returnval = "( ";

        if (startdate != null) {
            returnval += (MATCH_WITH_SQLNAMES[(type * 2) + matchwith] + " >= " +
            startdate.getTime() + " ");

            if (enddate != null) {
                returnval += " AND ";
            }
        }

        if (enddate != null) {
            returnval += (MATCH_WITH_SQLNAMES[(type * 2) + matchwith] + " <= " + enddate.getTime() +
            " ");
        }

        returnval += " )";

        return returnval;
    }

    // getQueryString

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean isLegalQuery() {
        return !((startdate == null) && (enddate == null));
    }

    // Private Fields.
    private int matchwith;
    private int type;
    private Date startdate;
    private Date enddate;
}
