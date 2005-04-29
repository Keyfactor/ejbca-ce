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
 
package se.anatom.ejbca.authorization;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Collection;
import java.util.Iterator;
import java.io.Serializable;

/**
 * A class that represents a group of users and their access rules.
 *
 * @version $Id: AdminGroup.java,v 1.5 2005-04-29 08:16:10 anatom Exp $
 */
public class AdminGroup implements Serializable, Comparable {
                               
    
    /** Creates a new instance of AdminGroup */
    public AdminGroup(String admingroupname, int caid) {      
      this.admingroupname=admingroupname;
      this.caid=caid;  
      accessrules = new ArrayList();
      adminentities = new ArrayList();
    }

    public AdminGroup(int admingroupid, String admingroupname, int caid, ArrayList accessrules, ArrayList adminentities){
      this.admingroupid=admingroupid;
      this.admingroupname=admingroupname;
      this.caid=caid;
      this.accessrules=accessrules;
      this.adminentities=adminentities;
    }

    // Public methods
    /** Returns the number of accessrules applied to this admingroup */
    public int getNumberOfAccessRules() {
      return accessrules.size();
    }

    /** Returns a ArrayList of AccessRule containing all the admingroup's accessrules.*/
    public Collection getAccessRules() {
      return accessrules;
    }

    /** Returns the number of admin entities in this admingroup */
    public int getNumberAdminEntities() {
      return adminentities.size();
    }

    /** Returns an ArrayList of AdminEntity containing all the admingroup's admin entities.*/
    public Collection getAdminEntities() {
      return adminentities;
    }
    
    public int getCAId(){
      return this.caid;
    }
    
    public int getAdminGroupId(){
      return this.admingroupid;	
    }
    
    public String getAdminGroupName(){
      return this.admingroupname;
    }
    
    /** Method that given an array of available access rules returns which isn't already
     * in use by the rule set. */
    public Collection nonUsedAccessRules(Collection availableaccessrules){
      ArrayList nonusedaccessrules = new ArrayList();
      int result;
      Collections.sort(accessrules);
      if(availableaccessrules != null){
        Iterator iter = availableaccessrules.iterator();
        while(iter.hasNext()){
          String availableaccessrule = (String) iter.next();   
          result=java.util.Collections.binarySearch(accessrules,new AccessRule(availableaccessrule, 0, false));
          if(result < 0){
            // Access rule isn't in use.
            nonusedaccessrules.add(availableaccessrule);
          }
        }
      }
      return nonusedaccessrules;
    }
    
 
    public int compareTo(Object o) {
        if(caid != ((AdminGroup) o).getCAId())
            return caid - ((AdminGroup) o).getCAId();
        return admingroupname.compareTo(((AdminGroup)o).getAdminGroupName());              
    }
    
    // Private methods

    // Private fields
    private int       admingroupid;
    private String    admingroupname;
    private int       caid;
    private ArrayList accessrules;
    private ArrayList adminentities;
 }
