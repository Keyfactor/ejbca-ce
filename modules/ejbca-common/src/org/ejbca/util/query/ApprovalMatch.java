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
 * @version $Id$
 *
 * @see org.ejbca.util.query.BasicMatch
 * @see org.ejbca.util.query.TimeMatch
 * @see org.ejbca.util.query.ApprovalMatch
 */
public class ApprovalMatch extends BasicMatch {
    // Public Constants

	private static final long serialVersionUID = -4891299802473333801L;
    public static final int MATCH_WITH_UNIQUEID                      = 0;
    public static final int MATCH_WITH_APPROVALID                    = 1;
    public static final int MATCH_WITH_APPROVALTYPE                  = 2;
    public static final int MATCH_WITH_ENDENTITYPROFILEID            = 3;
    public static final int MATCH_WITH_CAID                          = 4;
    public static final int MATCH_WITH_REQUESTADMINCERTISSUERDN      = 5;
    public static final int MATCH_WITH_REQUESTADMINCERTSERIALNUMBER  = 6;
    public static final int MATCH_WITH_STATUS                        = 7; 
    public static final int MATCH_WITH_REMAININGAPPROVALS            = 8;

    


    // Private Constants. These refer to column names in the database and are used for native SQL querying.
    private static final String[] MATCH_WITH_SQLNAMES = { "id", "approvalId", "approvalType", "endEntityProfileId", "cAId", "reqAdminCertIssuerDn",
            "reqAdminCertSn", "status", "remainingApprovals" }; // Represents the column names in approvals table.   
    
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
    public ApprovalMatch(int matchwith, int matchtype, String matchvalue)
        throws NumberFormatException {
        this.matchwith = matchwith;
        this.matchtype = matchtype;
        this.matchvalue = matchvalue;

        // The row below does not do anthing but check that matchvalue contains
        // a legal number value when matching number field. See @throws clause.
        if (matchwith != MATCH_WITH_REQUESTADMINCERTISSUERDN &&
        	matchwith != MATCH_WITH_REQUESTADMINCERTSERIALNUMBER){
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
			// Because some databases (read JavaDB/Derby) does not allow matching of integer with a string expression
			// like "where status='10'" instead of "where status=10", we have to hav e some special handling here.
			String stringChar = "'";
	        if ((matchwith >= MATCH_WITH_UNIQUEID && matchwith <= MATCH_WITH_CAID) || (matchwith == MATCH_WITH_STATUS) || (matchwith == MATCH_WITH_REMAININGAPPROVALS)) {
				stringChar = "";
	        }
			returnval = MATCH_WITH_SQLNAMES[matchwith] + " = "+stringChar + matchvalue + stringChar;
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
