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
 
package org.ejbca.ui.web.admin.rainterface;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * A class representing a set of users
 * 
 * @version $Id$
 */
public class UsersView implements Serializable {
        
    private static final long serialVersionUID = -7382135359016557800L;
    /** Creates a new instance of UsersView */
    public UsersView() {
      users = new ArrayList<UserView>();
      sortby = new SortBy();
    }
    
    public UsersView(EndEntityInformation importuser, HashMap<Integer, String> caidtonamemap){
      users = new ArrayList<UserView>();
      sortby = new SortBy();        
      users.add(new UserView(importuser, caidtonamemap)); 
      
      Collections.sort(users); 
    }
    
    public UsersView(Collection<EndEntityInformation> importusers, HashMap<Integer, String>caidtonamemap){ 
      users = new ArrayList<UserView>();
      sortby = new SortBy();
      
      setUsers(importusers, caidtonamemap);
    }
    // Public methods.
    
    public void sortBy(int sortby, int sortorder) {
      this.sortby.setSortBy(sortby);
      this.sortby.setSortOrder(sortorder);
      
      Collections.sort(users);
    }
    
    public UserView[] getUsers(int index, int size) {       
      int endindex;  
      UserView[] returnval;
   
      if(index > users.size()) {
    	  index = users.size()-1;
      }
      if(index < 0) {
    	  index =0;
      }
      
      // The below is used in order to return all the values in one page
      // JasperReports has its own multiple page setings (right now it will print all pages inside a single web page, one after the other)
      // i think this functions were first used in very specific places, where the user asks directly for a single page at once depending on the number of
      // results in one page.  If this number is -1 then all results will be on one single page
      if (size == -1)  {
    	  endindex = users.size();
      } else {
    	  endindex = index + size;
    	  if(endindex > users.size()) {
    		  endindex = users.size();
    	  }
      }
      
      returnval = new UserView[endindex-index];  
      
      int end = endindex - index;
      for(int i = 0; i < end; i++){
        returnval[i] = (UserView) users.get(index+i);   
      }
      
      return returnval;
    }
    
    public void setUsers(UserView[] users) {
      this.users.clear();
      if(users !=null && users.length > 0){       
        for(int i=0; i < users.length; i++){
          users[i].setSortBy(this.sortby);
          this.users.add(users[i]);
        }
      }
      Collections.sort(this.users);
    }
    
    public void setUsers(EndEntityInformation[] users, Map<Integer, String> caidtonamemap) {
      UserView user;  
      this.users.clear();
      if(users !=null && users.length > 0){ 
        for(int i=0; i< users.length; i++){
          user = new UserView(users[i], caidtonamemap); 
          user.setSortBy(this.sortby);
          this.users.add(user);
        }
        Collections.sort(this.users);
      }
    }

    public void setUsers(Collection<EndEntityInformation> importusers, Map<Integer, String> caidtonamemap) { 
        
      UserView user;  
      Iterator<EndEntityInformation> i;  
      this.users.clear();
      if(importusers!=null && importusers.size() > 0){
        i=importusers.iterator();
        while(i.hasNext()){
        	EndEntityInformation nextuser = (EndEntityInformation) i.next();  
          user = new UserView(nextuser, caidtonamemap); 
          user.setSortBy(this.sortby);
          users.add(user);
        }
        Collections.sort(users);
      }
    }

    public void addUser(UserView user) {
       user.setSortBy(this.sortby);        
       users.add(user);
    }
    
    public int size(){
      return users.size();   
    }
    
    public void clear(){
      this.users.clear();   
    }
    // Private fields
    private List<UserView> users;
    private SortBy sortby;
    
}
