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
import java.util.Iterator;

import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;

/**
 * A class that looks up the which modules a administrator have right to view.
 * This is done by looking up an administrators privileges in the tree and returning a string to be used in SQL-queries.
 * 
 * @version $Id$
 */
public class LogAuthorization implements Serializable {
    
    private String querystring = null;
    private String caidstring = null;
    private Collection authorizedmodules = null;
    private IAuthorizationSessionLocal authorizationsession;
    private ICAAdminSessionLocal caAdminSession;
    private Admin administrator;
    
    /** Creates a new instance of LogAuthorization. */
    public LogAuthorization(Admin administrator, IAuthorizationSessionLocal authorizationsession, ICAAdminSessionLocal caAdminSession) {
       this.administrator = administrator;
       this.authorizationsession = authorizationsession;
       this.caAdminSession = caAdminSession;
    }

    /**
     * Method that checks the administrators view log privileges to the different modules and returns a string that should be used in where clause of SQL queries.
     *
     * @return a string of log module privileges that should be used in the where clause of SQL queries.
     */
    public String getViewLogRights() {      
      if(querystring == null){
        querystring = "";  
        boolean first = true;
        boolean authorized = false;
        
        for(int i = 0 ; i < LogConstants.MODULETEXTS.length; i++){
          authorized = false; 
          String resource = AccessRulesConstants.VIEWLOGACCESSRULES[i];
          try{ 
            authorized = this.authorizationsession.isAuthorizedNoLog(administrator,resource);
          }catch(AuthorizationDeniedException e){} 
          if(authorized){
            if(first){
              querystring = "(";
              first = false;
            }
            else
             querystring += " OR ";
             
            querystring += "module=" + i;
          }  
        }
       
       if(!querystring.equals(""))
        querystring += ")";
        
     }   
              
      return querystring; 
    } 
    
    /**
     * Method that checks the administrators view log privileges to the different CAs and returns a string that should be used in where clause of SQL queries.
     *
     * @return a string of log module privileges that should be used in the where clause of SQL queries.
     */
    public String getCARights(){
      if(caidstring == null){
        caidstring = "";
        
        Iterator iter = caAdminSession.getAvailableCAs(administrator).iterator();
         
        try{ 
          this.authorizationsession.isAuthorizedNoLog(administrator, "/super_administrator");
          caidstring = " cAId = " + LogConstants.INTERNALCAID;       
        }catch(AuthorizationDeniedException e){} 
      
        
        while(iter.hasNext()){
          if(caidstring.equals(""))
            caidstring = " cAId = " + ((Integer) iter.next()).toString();   
          else    
            caidstring = caidstring + " OR cAId = " + ((Integer) iter.next()).toString(); 
        }                
          
      }  
      
      return caidstring;   
    }
    
    public void clear(){
      this.querystring = null;
      this.caidstring = null;
      this.authorizedmodules = null;
    }
    
    public Collection getAuthorizedModules(){    
       if(authorizedmodules == null){
	     authorizedmodules = new ArrayList();
	     
	     for(int i=0; i < AccessRulesConstants.VIEWLOGACCESSRULES.length; i++){
	     	 try{
	     	 	this.authorizationsession.isAuthorizedNoLog(administrator,AccessRulesConstants.VIEWLOGACCESSRULES[i]);
				authorizedmodules.add(new Integer(i));
	         }catch(AuthorizationDeniedException ade){}  
	     }	             
      }    
       return authorizedmodules;
    }
}


