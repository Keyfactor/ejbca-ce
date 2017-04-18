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

import org.apache.commons.lang.StringUtils;

/**
 * A class used by Query class to build a custom query for EJBCA approval module.
 *
 * @version $Id$
 */
public class ApprovalMatch extends BasicMatch {

    private static final long serialVersionUID = -4891299802473333801L;

    /** Match with the id column (the primary key), for looking up a particular approval */
    public static final int MATCH_WITH_UNIQUEID                      = 0;
    /** Match with the computed id for the approval, for searching for identical approvals */
    public static final int MATCH_WITH_APPROVALID                    = 1;
    public static final int MATCH_WITH_APPROVALTYPE                  = 2;
    public static final int MATCH_WITH_ENDENTITYPROFILEID            = 3;
    public static final int MATCH_WITH_CAID                          = 4;
    public static final int MATCH_WITH_REQUESTADMINCERTISSUERDN      = 5;
    public static final int MATCH_WITH_REQUESTADMINCERTSERIALNUMBER  = 6;
    public static final int MATCH_WITH_STATUS                        = 7; 
    public static final int MATCH_WITH_REMAININGAPPROVALS            = 8;

    /** These refer to column names in the database and are used for native SQL querying. */
    private static final String[] MATCH_WITH_SQLNAMES = {
        "id", "approvalId", "approvalType", "endEntityProfileId", "cAId", "reqAdminCertIssuerDn", "reqAdminCertSn", "status", "remainingApprovals"
    };

    private int matchwith;
    private int matchtype;
    private String matchvalue;

    /**
     * Creates a new instance.
     *
     * @param matchwith determines which field in approval table to match with.
     * @param matchtype determines how to match the field..
     * @param matchvalue the value to match with.
     *
     * @throws NumberFormatException if matchvalue contains illegal numbervalue when matching number field.
     */
    public ApprovalMatch(final int matchwith, final int matchtype, final String matchvalue)
        throws NumberFormatException {
        this.matchwith = matchwith;
        this.matchtype = matchtype;
        this.matchvalue = matchvalue;
        // The row below does not do anything but check that matchvalue contains
        // a legal number value when matching number field. See @throws clause.
        if (matchwith != MATCH_WITH_REQUESTADMINCERTISSUERDN &&
            matchwith != MATCH_WITH_REQUESTADMINCERTSERIALNUMBER){
            Integer.valueOf(matchvalue);
        }
    }

    @Override
    public String getQueryString() {
        String returnval = "";
        final String matchvalue = super.escapeSql(this.matchvalue);
        if (matchtype == BasicMatch.MATCH_TYPE_EQUALS) {
            // Because some databases (read JavaDB/Derby) does not allow matching of integer with a string expression
            // like "where status='10'" instead of "where status=10", we have to hav e some special handling here.
            String stringChar = "'";
            if ((matchwith >= MATCH_WITH_UNIQUEID && matchwith <= MATCH_WITH_CAID) || (matchwith == MATCH_WITH_STATUS) || (matchwith == MATCH_WITH_REMAININGAPPROVALS)) {
                stringChar = "";
            }
            returnval = MATCH_WITH_SQLNAMES[matchwith] + " = "+stringChar + matchvalue.trim() + stringChar;
        }
        if (matchtype == BasicMatch.MATCH_TYPE_BEGINSWITH) {
            returnval = MATCH_WITH_SQLNAMES[matchwith] + " LIKE '" + matchvalue + "%'";
        }
        if (matchtype == BasicMatch.MATCH_TYPE_CONTAINS) {
            returnval = MATCH_WITH_SQLNAMES[matchwith] + " LIKE '%" + matchvalue + "%'";
        }
        return returnval;
    }

    @Override
    public boolean isLegalQuery() {
        return StringUtils.isNotBlank(matchvalue);
    }
}
