/*
 * UserGroups.java
 *
 * Created on den 21 mars 2002, 02:36
 */

package se.anatom.ejbca.webdist.ejbcaathorization;
import java.util.TreeMap;
import java.io.Serializable;



/**
 * A class that represents a set of usergroups. The set is actually a Treemap.
 *
 * @author  Philip Vendil
 */
public class UserGroups implements Serializable {
  
    /** Creates a new instance of UserGroups */
    public UserGroups() {
      usergroups = new TreeMap(); 
    }
    
    // Public methods
    /** Method to add an usergroup. Throws UsergroupExitsException if user already exists  */
    public void addUserGroup(String name, UserGroup usergroup) throws UsergroupExistsException {
      UserGroup ug = (UserGroup) usergroups.get(name);
      if(ug != null)
        throw new UsergroupExistsException(name);
      usergroups.put(name,usergroup);
    }
    
    /** Method to remove a usergroup.*/ 
    public void removeUserGroup(String name) {
        usergroups.remove(name);
    }
    
    /** Metod to rename a usergroup */
    public void renameUserGroup(String oldname, String newname) throws UsergroupExistsException{
      UserGroup ug = (UserGroup) usergroups.get(newname);
      if(ug != null){
        throw new UsergroupExistsException(newname);        
      }
      else{
        ug = (UserGroup) usergroups.get(oldname);
        if(ug != null){
          usergroups.put(newname,ug);    
          usergroups.remove(oldname); 
        }
      } 
    }
    
      /** Method to get a reference to a usergroup.*/ 
    public UserGroup getUserGroup(String name) {
        return (UserGroup) usergroups.get(name);
    }  
        
    /** Returns the number of usergroups */
    public int getNumberOfUserGroups() {
      return usergroups.size();
    }
    
    /** Returns an array containing all the usergroups names.*/
     public String[] getUserGroupnames() {
      String[] dummy={};  
      return (String[]) usergroups.keySet().toArray(dummy);  
    }
    
    /** Returns an array containing all the usergroups.*/
    public UserGroup[] getUserGroups() {
      UserGroup[] dummy={};  
      return (UserGroup[]) usergroups.values().toArray(dummy);  
    }
    
    // Private methods
    
    // Private fields
    private TreeMap usergroups;
 }



