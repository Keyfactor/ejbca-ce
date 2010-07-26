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
 
package org.ejbca.core.model.authorization;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Collection;
import java.util.Iterator;
import java.io.Serializable;

/**
 * A class that represents a group of users and their access rules.
 *
 * @version $Id$
 */
public class AdminGroup implements Serializable, Comparable<Object> {
                               
    public static final String DEFAULTGROUPNAME = "DEFAULT";
    public static final String PUBLICWEBGROUPNAME = "Public Web Users";
    public static final String TEMPSUPERADMINGROUP = "Temporary Super Administrator Group";
    
    private int admingroupid;
    private String admingroupname;
    private ArrayList<AccessRule> accessrules;
    private ArrayList<AdminEntity> adminentities;

    /** Creates a new instance of AdminGroup */
    public AdminGroup(String admingroupname) {      
      this.admingroupname = admingroupname;
      accessrules = new ArrayList<AccessRule>();
      adminentities = new ArrayList<AdminEntity>();
    }

    public AdminGroup(int admingroupid, String admingroupname, ArrayList<AccessRule> accessrules, ArrayList<AdminEntity> adminentities){
      this.admingroupid = admingroupid;
      this.admingroupname = admingroupname;
      this.accessrules = accessrules;
      this.adminentities = adminentities;
    }

    /** Returns the number of accessrules applied to this admingroup */
    public int getNumberOfAccessRules() {
      return accessrules.size();
    }

    /** Returns a ArrayList of AccessRule containing all the admingroup's accessrules.*/
    public Collection<AccessRule> getAccessRules() {
      return accessrules;
    }

    /** Returns the number of admin entities in this admingroup */
    public int getNumberAdminEntities() {
      return adminentities.size();
    }

    /** Returns an ArrayList of AdminEntity containing all the admingroup's admin entities.*/
    public Collection<AdminEntity> getAdminEntities() {
      return adminentities;
    }
    
    public int getAdminGroupId(){
      return this.admingroupid;	
    }
    
    public String getAdminGroupName(){
      return this.admingroupname;
    }
    
    /** Method that given an array of available access rules returns which isn't already
     * in use by the rule set. */
    public Collection<String> nonUsedAccessRules(Collection<String> availableaccessrules){
      ArrayList<String> nonusedaccessrules = new ArrayList<String>();
      int result;
      Collections.sort(accessrules);
      if(availableaccessrules != null){
        Iterator<String> iter = availableaccessrules.iterator();
        while(iter.hasNext()){
          String availableaccessrule = iter.next();   
          result = Collections.binarySearch(accessrules,new AccessRule(availableaccessrule, 0, false));
          if(result < 0){
            // Access rule isn't in use.
            nonusedaccessrules.add(availableaccessrule);
          }
        }
      }
      return nonusedaccessrules;
    }
    
    /** Method that given an array of available access rules returns which isn't already
     * in use by the rule set. */
    public Collection<AccessRule> nonUsedAccessRuleObjects(Collection<String> availableaccessrules){
      ArrayList<AccessRule> nonusedaccessrules = new ArrayList<AccessRule>();
      int result;
      Collections.sort(accessrules);
      if(availableaccessrules != null){
        Iterator<String> iter = availableaccessrules.iterator();
        while(iter.hasNext()){
          String availableaccessrule = iter.next();   
          result = Collections.binarySearch(accessrules,new AccessRule(availableaccessrule, 0, false));
          if(result < 0){
            // Access rule isn't in use.
            nonusedaccessrules.add(new AccessRule(availableaccessrule, 0, false));
          }
        }
      }
      return nonusedaccessrules;
    }

    public int compareTo(Object o) {
        return admingroupname.compareTo(((AdminGroup)o).getAdminGroupName());              
    }    
}
