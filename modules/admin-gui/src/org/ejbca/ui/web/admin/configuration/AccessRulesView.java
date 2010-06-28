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
 
package org.ejbca.ui.web.admin.configuration;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AccessRulesConstants;


/**
 * A class used as a help class for displaying access rules
 *
 * @author  TomSelleck
 * @version $Id: AccessRulesView.java 9005 2010-05-04 12:09:54Z anatom $ 
 */
public class AccessRulesView implements java.io.Serializable {

    
    /**
     * Creates an AccessRulesView and sorts the accessrules into their approriate
     * sets.
     */
    public AccessRulesView(Collection accessrules){
      this.rolebasedaccessrules = new ArrayList();
      this.regularaccessrules = new ArrayList();
      this.endentityprofileaccessrules = new ArrayList();
      this.caaccessrules = new ArrayList();
      this.userdatasourceaccessrules = new ArrayList();
        
        
      Iterator iter = accessrules.iterator();
      while(iter.hasNext()){
        Object obj = iter.next();
        String accessrulestring = "";
        AccessRule accessrule = null;
        if( obj instanceof AccessRule ){
          accessrulestring = ((AccessRule) obj).getAccessRule();
          accessrule = (AccessRule) obj;
        }else{
          accessrulestring = (String) obj;
          accessrule = new AccessRule(accessrulestring, 0,  false);
        }  
        boolean regular = true;
        
        // Check if rule is a role based one
        for(int i=0; i< AccessRulesConstants.ROLEACCESSRULES.length; i++){
           if(accessrulestring.equals(AccessRulesConstants.ROLEACCESSRULES[i])){
             this.rolebasedaccessrules.add(accessrule);
             regular=false;
           }  
        }
        
        // Check if rule is end entity profile access rule
        if(accessrulestring.startsWith("/endentityprofilesrules")){
          this.endentityprofileaccessrules.add(accessrule);
          regular=false;
        }
        
        // Check if rule is CA access rule
        if(accessrulestring.startsWith(AccessRulesConstants.CAPREFIX) || accessrulestring.equals(AccessRulesConstants.CABASE)){
          this.caaccessrules.add(accessrule);
          regular=false;
        }
        
        // Check if rule is end entity profile access rule
        if(accessrulestring.startsWith(AccessRulesConstants.USERDATASOURCEBASE)){
          this.userdatasourceaccessrules.add(accessrule);
          regular=false;
        }
        
        // Otherwise it's a regular accessrule.
        if(regular) {
          this.regularaccessrules.add(accessrule);  
        }
      } 
      
      Collections.sort(this.rolebasedaccessrules);
      Collections.sort(this.regularaccessrules);
      Collections.sort(this.endentityprofileaccessrules);
      Collections.sort(this.caaccessrules);
      Collections.sort(this.userdatasourceaccessrules);
      
    }
    
   
    /**
     *  Method that returns all role based access rules, sorted.
     */
    public Collection getRoleBasedAccessRules(){
      return this.rolebasedaccessrules;   
    }

    /**
     *  Method that returns all regular access rules, sorted.
     */    
    public Collection getRegularAccessRules(){
      return this.regularaccessrules;   
    }
    
    /**
     *  Method that returns all end entity profile access rules, sorted.
     */    
    public Collection getEndEntityProfileAccessRules(){
      return this.endentityprofileaccessrules;   
    }

    /**
     *  Method that returns all CA access rules, sorted.
     */
    public Collection getCAAccessRules(){
      return this.caaccessrules;   
    }    

    /**
     *  Method that returns all User Data Source access rules, sorted.
     */
    public Collection getUserDataSourceAccessRules(){
      return this.userdatasourceaccessrules;   
    }
    
    // Private constants.  
    
    // Private methods.
    private ArrayList rolebasedaccessrules;
    private ArrayList regularaccessrules;
    private ArrayList endentityprofileaccessrules;
    private ArrayList userdatasourceaccessrules;
    private ArrayList caaccessrules;
}
