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

import java.util.Date;

import org.apache.log4j.Logger;

/**
 * A class used by Query class to build a query for EJBCA RA modules.
 *
 * @version $Id$
 */
public class TimeMatch extends BasicMatch {

    private static final long serialVersionUID = 555503673432162539L;
    private static final Logger log = Logger.getLogger(TimeMatch.class);

	/** UserMatch Specific Constant */	
    public static final int MATCH_WITH_TIMECREATED = 0;
    /** UserMatch Specific Constant */
    public static final int MATCH_WITH_TIMEMODIFIED = 1;
    
    /** ApprovalMatch Specific Constant */
    public static final int MATCH_WITH_REQUESTORAPPROVALTIME = 0;
    /** ApprovalMatch Specific Constant */
    public static final int MATCH_WITH_EXPIRETIME = 1;

    /** Represents the column names in (log,) UserData and ApprovalData tables. */
    private static final String[] MATCH_WITH_SQLNAMES = {
        "", "", "timeCreated", "timeModified", "requestDate", "expireDate"
    };

    private final int matchwith;
    private final int type;
    private final Date startdate;
    private final Date enddate;

    /**
     * Creates a new instance of TimeMatch. Constructor should only be used in ra user queries.
     *
     * @param type uses Query class constants to determine if it's a log query or ra query.
     * @param matchwith should be one of MATCH_WITH constants to determine with field to search.
     *        Only used in ra user queries.
     * @param startdate gives a startdate for the query, null if not needed.
     * @param enddate gives a enddate for the query, null if not needed.
     */
    public TimeMatch(int type, int matchwith, Date startdate, Date enddate) {
        this.type = type;
        this.matchwith = matchwith;
        this.startdate = startdate;
        this.enddate = enddate;
    }

    /**
     * Creates a new instance of TimeMatch.
     *
     * @param type uses Query class constants to determine if it's a log query or ra query.
     * @param startdate gives a startdate for the query, null if not needed.
     * @param enddate gives a enddate for the query, null if not needed.
     */
    public TimeMatch(int type, Date startdate, Date enddate) {
        this(type, MATCH_WITH_TIMECREATED, startdate, enddate);
    }

    @Override
    public String getQueryString() {
        String returnval = "( ";
        if (startdate != null) {
            if (log.isDebugEnabled()) {
                log.debug("Making match with startdate: "+startdate);
            }
            returnval += (MATCH_WITH_SQLNAMES[(type * 2) + matchwith] + " >= " +
            startdate.getTime() + " ");
            if (enddate != null) {
                returnval += " AND ";
            }
        }
        if (enddate != null) {
            if (log.isDebugEnabled()) {
                log.debug("Making match with enddate: "+enddate);
            }
            returnval += (MATCH_WITH_SQLNAMES[(type * 2) + matchwith] + " <= " + enddate.getTime() +
            " ");
        }
        returnval += " )";
        return returnval;
    }

    @Override
    public boolean isLegalQuery() {
        return startdate != null || enddate != null;
    }
}
