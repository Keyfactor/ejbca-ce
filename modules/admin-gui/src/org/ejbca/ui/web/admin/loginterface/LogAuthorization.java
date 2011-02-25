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
 
package org.ejbca.ui.web.admin.loginterface;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;

import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CaSession;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;

/**
 * A class that looks up the which modules a administrator have right to view.
 * This is done by looking up an administrators privileges in the tree and returning a string to be used in SQL-queries.
 * 
 * @version $Id$
 */
public class LogAuthorization implements Serializable {
    
    private static final long serialVersionUID = 5643565073694963982L;
    private String querystring = null;
    private String caidstring = null;
    private Collection<Integer> authorizedmodules = null;
    private AuthorizationSession authorizationsession;
    private CaSession caSession;
    private Admin administrator;
    
    /** Creates a new instance of LogAuthorization. */
    public LogAuthorization(Admin administrator, AuthorizationSession authorizationsession, CaSession caSession) {
       this.administrator = administrator;
       this.authorizationsession = authorizationsession;
       this.caSession = caSession;
    }

    /**
     * Method that checks the administrators view log privileges to the different modules and returns a string that should be used in where clause of SQL queries.
     *
     * @return a string of log module privileges that should be used in the where clause of SQL queries.
     */
    public String getViewLogRights() {
        if (querystring == null) {
            querystring = "";
            boolean first = true;

            for (int i = 0; i < LogConstants.MODULETEXTS.length; i++) {

                String resource = AccessRulesConstants.VIEWLOGACCESSRULES[i];

                if (authorizationsession.isAuthorizedNoLog(administrator, resource)) {
                    if (first) {
                        querystring = "(";
                        first = false;
                    } else {
                        querystring += " OR ";
                    }
                    querystring += "module=" + i;
                }
            }
            if (!querystring.equals("")) {
                querystring += ")";
            }
        }   
              
      return querystring; 
    } 
    
    /**
     * Method that checks the administrators view log privileges to the different CAs and returns a string that should be used in where clause of SQL queries.
     *
     * @return a string of log module privileges that should be used in the where clause of SQL queries.
     */
    public String getCARights() {
        if (caidstring == null) {
            caidstring = "";

            if (authorizationsession.isAuthorizedNoLog(administrator, "/super_administrator")) {
                // Superadmin authorized to all
                caidstring = " caId = " + LogConstants.INTERNALCAID;
            }

            for (Integer caId : caSession.getAvailableCAs(administrator)) {
                if (caidstring.equals("")) {
                    caidstring = " caId = " + caId;
                } else {
                    caidstring = caidstring + " OR caId = " + caId;
                }
            }
        }
        return caidstring;
    }
    
    public void clear(){
      this.querystring = null;
      this.caidstring = null;
      this.authorizedmodules = null;
    }
    
    public Collection<Integer> getAuthorizedModules() {
        if (authorizedmodules == null) {
            authorizedmodules = new ArrayList<Integer>();

            for (int i = 0; i < AccessRulesConstants.VIEWLOGACCESSRULES.length; i++) {
                if (authorizationsession.isAuthorizedNoLog(administrator, AccessRulesConstants.VIEWLOGACCESSRULES[i])) {
                    authorizedmodules.add(i);
                }

            }
        }
        return authorizedmodules;
    }
}


