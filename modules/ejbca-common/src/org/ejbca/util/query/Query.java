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
 * Query.java
 *
 * Created on den 23 juli 2002, 01:24
 */
package org.ejbca.util.query;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.util.StringTools;

/**
 * A class used to produce advanced querys from the log and user data tables. It's main function is
 * getQueryString which returns a string which should be placed in the 'WHERE' clause of a SQL
 * statement.
 *
 * @version $Id$
 */
public class Query implements Serializable {

    private static final long serialVersionUID = 2020709050743730820L;
 
    private static Logger log = Logger.getLogger(Query.class);
    // Public Constants.
    public static final int TYPE_LOGQUERY = 0;
    public static final int TYPE_USERQUERY = 1;
    public static final int TYPE_APPROVALQUERY = 2;
    public static final int CONNECTOR_AND = 0;
    public static final int CONNECTOR_OR = 1;
    public static final int CONNECTOR_ANDNOT = 2;
    public static final int CONNECTOR_ORNOT = 3;


    // Private Constants.
    static final String[] CONNECTOR_SQL_NAMES = { " AND ", " OR ", " AND NOT ", " OR NOT " };

    // Private fields.
    final private List<BasicMatch> matches; // Should only contain BasicMatch objects.
    final private List<Integer> connectors; // Should only containg CONNECTOR constants.
    final protected int type;
    private boolean hasIllegalSqlChars = false;
    
    // Public methods.

    /**
     * Creates a new instance of Query
     *
     * @param type is the typ of query to produce. Should be one of the 'TYPE' constants of this
     *        class.
     */
    public Query(int type) {
        matches = new ArrayList<BasicMatch>();
        connectors = new ArrayList<Integer>();
        this.type = type;
    }

    /**
     * Adds a time restraint to the query. Both parameter cannot be null This method should only be
     * used in ra user queries.
     *
     * @param startdate gives the start date of the query or null if it no startdate.
     * @param enddate gives the end date of the query or null if it no startdate.
     */
    public void add(Date startdate, Date enddate) {
        matches.add(new TimeMatch(type, startdate, enddate));
    }

    /**
     * Adds a time restraint to the query. Both start and enddate parameters cannot be null This
     * method should only be used in ra user queries.
     *
     * @param matchwith should indicate which field to match with, on of the TimeMatch.MATCH_WITH
     *        constants.
     * @param startdate gives the start date of the query or null if it no startdate.
     * @param enddate gives the end date of the query or null if it no startdate.
     */
    public void add(int matchwith, Date startdate, Date enddate) {
        matches.add(new TimeMatch(type, matchwith, startdate, enddate));
    }

    /**
     * Adds a time restraint and a connector to the query. Both parameter cannot be null. This
     * method should only be used in log queries.
     *
     * @param startdate gives the start date of the query or null if it no startdate.
     * @param enddate gives the end date of the query or null if it no startdate.
     * @param connector should be one of the 'CONNECTOR' constants.
     */
    public void add(Date startdate, Date enddate, int connector) {
        matches.add(new TimeMatch(type, startdate, enddate));
        connectors.add(Integer.valueOf(connector));
    }

    /**
     * Adds a time restraint and a connector to the query. Both start and enddate parameters cannot
     * be null. This method should only be used in ra user queries.
     *
     * @param matchwith should indicate which field to match with, on of the TimeMatch.MATCH_WITH
     *        constants.
     * @param startdate gives the start date of the query or null if it no startdate.
     * @param enddate gives the end date of the query or null if it no startdate.
     * @param connector should be one of the 'CONNECTOR' constants.
     */
    public void add(int matchwith, Date startdate, Date enddate, int connector) {
        matches.add(new TimeMatch(type, matchwith, startdate, enddate));
        connectors.add(Integer.valueOf(connector));
    }

    /**
     * Adds a match ot type UserMatch or LogMatch to the query.
     *
     * @param matchwith should be one of the the UserMatch.MATCH_WITH or LogMatch.MATCH_WITH
     *        connstants depending on query type.
     * @param matchtype should be one of BasicMatch.MATCH_TYPE constants.
     * @param matchvalue should be a string representation to match against.
     *
     * @throws NumberFormatException if there is an illegal character in matchvalue string.
     */
    public void add(int matchwith, int matchtype, String matchvalue)
        throws NumberFormatException {
        switch (this.type) {
        case TYPE_LOGQUERY:
            matches.add(new LogMatch(matchwith, matchtype, matchvalue));
            break;
        case TYPE_USERQUERY:
            matches.add(new UserMatch(matchwith, matchtype, matchvalue));
            break;
        case TYPE_APPROVALQUERY:
        	matches.add(new ApprovalMatch(matchwith, matchtype, matchvalue));
        	break;
        }
        if (StringTools.hasSqlStripChars(matchvalue)) {
            hasIllegalSqlChars = true;
        }
    }

    /**
     * Adds a match ot type UserMatch or LogMatch ant a connector to the query.
     *
     * @param matchwith should be one of the the UserMatch.MATCH_WITH or LogMatch.MATCH_WITH
     *        connstants depending on query type.
     * @param matchtype should be one of BasicMatch.MATCH_TYPE constants.
     * @param matchvalue should be a string representation to match against.
     * @param connector should be one of the 'CONNECTOR' constants.
     *
     * @throws NumberFormatException if there is an illegal character in matchvalue string.
     */
    public void add(int matchwith, int matchtype, String matchvalue, int connector)
        throws NumberFormatException {
        add(matchwith,matchtype,matchvalue);
        connectors.add(Integer.valueOf(connector));

 
    }

    /**
     * Adds a connector to the query.
     *
     * @param connector should be one of the 'CONNECTOR' constants.
     *
     * @throws NumberFormatException if there is an illegal character in matchvalue string.
     */
    public void add(int connector) {
        connectors.add(Integer.valueOf(connector));
    }

    /**
     * Gives the string to be used in the 'WHERE' clause int the SQL-statement.
     *
     * @return the string to be used in the 'WHERE'-clause.
     */
    public String getQueryString() {
        String returnval = "";
        for (int i = 0; i < (matches.size() - 1); i++) {
            returnval += ((BasicMatch) matches.get(i)).getQueryString();
            returnval += CONNECTOR_SQL_NAMES[((Integer) connectors.get(i)).intValue()];
        }
        returnval += ((BasicMatch) matches.get(matches.size() - 1)).getQueryString();

        return returnval;
    }

    /**
     * Checks if the present query is legal by checking if every match is legal and that the number
     * of connectors is one less than matches.
     *
     * @return true if the query is legal, false otherwise
     */
    public boolean isLegalQuery() {
        boolean returnval = true;
        for (BasicMatch match : matches) {
            returnval = returnval && match.isLegalQuery();
            if (!returnval) {
                log.error("Query is illegal: " + match.getQueryString());
            }
        }

        returnval = returnval && ((matches.size() - 1) == connectors.size());

        returnval = returnval && (matches.size() > 0);

        return returnval && !hasIllegalSqlChars();
    }

    /**
     * Checks if the present query contains illegal SQL string charcters as set by add(String) methods.
     * The add(String) methods checks against StringTools.hasStripChars.
     *
     * @return true if the query is legal, false otherwise
     * @see org.cesecore.util.StringTools#hasSqlStripChars(String)
     */
    public boolean hasIllegalSqlChars() {
        log.debug("hasIllegalSqlChars: "+hasIllegalSqlChars);
        return hasIllegalSqlChars;
    }

    /** 
     * @return the current query string 
     */
    @Override
    public String toString() {
        return getQueryString();
    }
}
