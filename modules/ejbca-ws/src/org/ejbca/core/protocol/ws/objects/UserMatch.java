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
package org.ejbca.core.protocol.ws.objects;

import org.ejbca.util.query.BasicMatch;

/**
 * Holder of user match/search data.
 * 
 * @version $Id$
 */
public class UserMatch {

    public static final int MATCH_WITH_USERNAME            = org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME;
    public static final int MATCH_WITH_EMAIL               = org.ejbca.util.query.UserMatch.MATCH_WITH_EMAIL;
    public static final int MATCH_WITH_STATUS              = org.ejbca.util.query.UserMatch.MATCH_WITH_STATUS; // Value must the number representation.
    public static final int MATCH_WITH_ENDENTITYPROFILE    = org.ejbca.util.query.UserMatch.MATCH_WITH_ENDENTITYPROFILE; // Matches the end entity profile name.
    public static final int MATCH_WITH_CERTIFICATEPROFILE  = org.ejbca.util.query.UserMatch.MATCH_WITH_CERTIFICATEPROFILE; // Matches the certificate profile name.
    public static final int MATCH_WITH_CA                  = org.ejbca.util.query.UserMatch.MATCH_WITH_CA; // Matches the CA name.
	public static final int MATCH_WITH_TOKEN               = org.ejbca.util.query.UserMatch.MATCH_WITH_TOKEN;
	public static final int MATCH_WITH_DN                  = org.ejbca.util.query.UserMatch.MATCH_WITH_DN;
    // Subject DN fields.
    public static final int MATCH_WITH_UID                 = org.ejbca.util.query.UserMatch.MATCH_WITH_UID;
    public static final int MATCH_WITH_COMMONNAME          = org.ejbca.util.query.UserMatch.MATCH_WITH_COMMONNAME;
    public static final int MATCH_WITH_DNSERIALNUMBER      = org.ejbca.util.query.UserMatch.MATCH_WITH_DNSERIALNUMBER;
    public static final int MATCH_WITH_GIVENNAME           = org.ejbca.util.query.UserMatch.MATCH_WITH_GIVENNAME;
    public static final int MATCH_WITH_INITIALS            = org.ejbca.util.query.UserMatch.MATCH_WITH_INITIALS;
    public static final int MATCH_WITH_SURNAME             = org.ejbca.util.query.UserMatch.MATCH_WITH_SURNAME;
    public static final int MATCH_WITH_TITLE               = org.ejbca.util.query.UserMatch.MATCH_WITH_TITLE;
    public static final int MATCH_WITH_ORGANIZATIONALUNIT  = org.ejbca.util.query.UserMatch.MATCH_WITH_ORGANIZATIONALUNIT;
    public static final int MATCH_WITH_ORGANIZATION        = org.ejbca.util.query.UserMatch.MATCH_WITH_ORGANIZATION;
    public static final int MATCH_WITH_LOCALITY            = org.ejbca.util.query.UserMatch.MATCH_WITH_LOCALITY;
    public static final int MATCH_WITH_STATEORPROVINCE     = org.ejbca.util.query.UserMatch.MATCH_WITH_STATEORPROVINCE;
    public static final int MATCH_WITH_DOMAINCOMPONENT     = org.ejbca.util.query.UserMatch.MATCH_WITH_DOMAINCOMPONENT;
    public static final int MATCH_WITH_COUNTRY             = org.ejbca.util.query.UserMatch.MATCH_WITH_COUNTRY;
	
    public static final int MATCH_TYPE_EQUALS     = BasicMatch.MATCH_TYPE_EQUALS;
    public static final int MATCH_TYPE_BEGINSWITH = BasicMatch.MATCH_TYPE_BEGINSWITH;
    public static final int MATCH_TYPE_CONTAINS   = BasicMatch.MATCH_TYPE_CONTAINS;
    
    private int matchwith;
    private int matchtype;
    private String matchvalue;
    
    /** Default Web Service Constructor */
    public UserMatch(){}
    
    /**
     * Constuctor to use to create a UserMatch.
     * 
     * @param matchwith  one of MATCH_WITH_ constants.
     * @param matchtype  one of MATCH_TYPE_ constants.
     * @param matchvalue a string to search for.
     */
    public UserMatch(int matchwith, int matchtype, String matchvalue){
    	this.matchwith  = matchwith;
    	this.matchtype  = matchtype;
    	this.matchvalue = matchvalue;    	
    }

	/**
	 * @return Returns the matchtype, one of MATCH_TYPE_ constants.
	 */
	public int getMatchtype() {
		return matchtype;
	}

	/**
	 * @param matchtype The matchtype to set, one of MATCH_TYPE_ constants.
	 */
	public void setMatchtype(int matchtype) {
		this.matchtype = matchtype;
	}

	/**
	 * @return Returns the matchvalue.
	 */
	public String getMatchvalue() {
		return matchvalue;
	}

	/**
	 * @param matchvalue The matchvalue to set.
	 */
	public void setMatchvalue(String matchvalue) {
		this.matchvalue = matchvalue;
	}

	/**
	 * @return Returns the matchwith, one of MATCH_WITH_ constants.
	 */
	public int getMatchwith() {
		return matchwith;
	}

	/**
	 * @param matchwith The matchwith to set, one of MATCH_WITH_ constants.
	 */
	public void setMatchwith(int matchwith) {
		this.matchwith = matchwith;
	}
	

}
