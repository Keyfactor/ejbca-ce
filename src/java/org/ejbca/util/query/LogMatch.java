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
 * LogMatch.java
 *
 * Created on den 28 aug 2002, 23:20
 */
package org.ejbca.util.query;

/**
 * A class used by Query class to build a query for ejbca log module. Inherits BasicMatch.  Main
 * function is getQueryString which returns a fragment of SQL statment.
 *
 * @author TomSelleck
 * @version $Id$
 *
 * @see org.ejbca.util.query.BasicMatch
 * @see org.ejbca.util.query.TimeMatch
 * @see org.ejbca.util.query.LogMatch
 */
public class LogMatch extends BasicMatch {
    // Public Constants

    private static final long serialVersionUID = -4306339790741595609L;
    public static final int MATCH_WITH_USERNAME         = 0;
    public static final int MATCH_WITH_ADMINCERTIFICATE = 1;
    public static final int MATCH_WITH_IP               = 2;
    public static final int MATCH_WITH_SPECIALADMIN     = 3;
    public static final int MATCH_WITH_CERTIFICATE      = 4;
    public static final int MATCH_WITH_COMMENT          = 5;
    public static final int MATCH_WITH_EVENT            = 6; // Value must the number representation.
    public static final int MATCH_WITH_MODULE           = 7;
    public static final int MATCH_WITH_CA               = 8;


    // Private Constants.
    static final String[] MATCH_WITH_SQLNAMES = {"username", "adminData", "adminData", "adminType"
                                                         , "certificateSNR", "logComment", "event", "module", "cAId"}; // Represents the column names in ra userdata table.
   
    
    // Public methods.

    /**
     * Creates a new instance of LogMatch.
     *
     * @param matchwith determines which field i logentry table to match with.
     * @param matchtype determines how to match the field..
     * @param matchvalue the value to match with.
     *
     * @throws NumberFormatException if matchvalue constains illegal numbervalue when matching
     *         number field.
     */
    public LogMatch(int matchwith, int matchtype, String matchvalue)
        throws NumberFormatException {
        this.matchwith = matchwith;
        this.matchtype = matchtype;
        this.matchvalue = matchvalue;

        // The row below does not do anything but check that matchvalue contains
        // a legal number value when matching number field. See @throws clause.
        if ((matchwith == MATCH_WITH_EVENT) || (matchwith == MATCH_WITH_SPECIALADMIN)) {
            Integer.valueOf(matchvalue);
        }
    }

    /**
     * Returns a SQL statement fragment from the given data.
     *
     * @return DOCUMENT ME!
     */
    public String getQueryString() {
        String returnval = "";

        if (matchtype == BasicMatch.MATCH_TYPE_EQUALS) {
        	String quote = "'";
        	switch(matchwith){
        	case MATCH_WITH_EVENT:
        	case MATCH_WITH_MODULE:
        	case MATCH_WITH_CA:
        	case MATCH_WITH_SPECIALADMIN:
        		quote = "";
        		break;
        	default:
        		quote = "'";
        	break;
        	}
            returnval = MATCH_WITH_SQLNAMES[matchwith] + " = " + quote + matchvalue + quote;
        }

        if (matchtype == BasicMatch.MATCH_TYPE_BEGINSWITH) {
            returnval = MATCH_WITH_SQLNAMES[matchwith] + " LIKE '" + matchvalue + "%'";
        }

        if (matchtype == BasicMatch.MATCH_TYPE_CONTAINS) {
            returnval = MATCH_WITH_SQLNAMES[matchwith] + " LIKE '%" + matchvalue + "%'";
        }

        return returnval;
    }

    // getQueryString

    /**
     * Checks if query data is ok.
     *
     * @return DOCUMENT ME!
     */
    public boolean isLegalQuery() {
        return !(matchvalue.trim().equals(""));
    }

    // Private Methods
    // Private Fields.
    private int matchwith;
    private int matchtype;
    private String matchvalue;
}
