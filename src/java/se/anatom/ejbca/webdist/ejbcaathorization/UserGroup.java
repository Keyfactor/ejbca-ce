/*
 * UserGroup.java
 *
 * Created on den 16 mars 2002, 14:02
 */

package se.anatom.ejbca.webdist.ejbcaathorization;
import java.util.Vector;
import java.io.Serializable;

import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;
/**
 * A class that represents a group of users and their access rules.
 *
 * @author  philip
 */
public class UserGroup implements Serializable {

    /** Creates a new instance of UserGroup */
    public UserGroup() {
      accessrules = new Vector(); 
      userentities = new Vector();
    }
    
    // Public methods
    /** Method to add an accesssrule to this usergroup */
    public void addAccessRule(String directory, int rule, boolean recursive) {
      accessrules.addElement(new AccessRule(directory,rule,recursive));
      // Sort the vector after directory names.
      java.util.Collections.sort(accessrules);
    }
    
    /** Method to remove access rule for this directory.*/ 
    public void removeAccessRule(String directory) {
      for (int i = 0; i < accessrules.size();i++){
        AccessRule ar = (AccessRule) accessrules.elementAt(i);
        if( ar.getDirectory().equals(directory.trim())){
          accessrules.removeElementAt(i);   
          i--;
        }
      }
    }
    
    /** Method to remove an access rule when index of it is known. */
    public void removeAccessRuleAt(int index){
      accessrules.removeElementAt(index);
    }
    
    /** Returns the number of accessrules applied to this usergroup */
    public int getNumberOfAccessRules() {
      return accessrules.size();
    }
    
    /** Returns an array containing all the usergroup's accessrules.*/
    public AccessRule[] getAccessRules() {
      AccessRule[] dummy={};  
      return (AccessRule[]) accessrules.toArray(dummy);  
    }
    
    /** Method to add an userentity to this usergroup */    
    public void addUserEntity(int matchwith, int matchtype, String matchvalue) {
      userentities.addElement(new UserEntity(matchwith,matchtype,matchvalue));
    }
    
    /** Method to remove an userentity with this matchvalue.*/ 
    public void removeUserEntity(int matchwith, int matchtype, String matchvalue) {
      for (int i = 0; i < userentities.size();i++){
        UserEntity ue = (UserEntity) userentities.elementAt(i);
        if( ue.getMatchValue().equals(matchvalue.trim()) && ue.getMatchWith() == matchwith
            &&  ue.getMatchType() == matchtype ){             
          userentities.removeElementAt(i);   
          i--;
        }
      }
    }
    
    /** Method to remove an user entity when index of it is known. */
    public void removeUserEntityAt(int index){
      userentities.removeElementAt(index);   
    }
  
    /** Returns the number of user entities in this usergroup */
    public int getNumberUserEntities() {
      return userentities.size();
    }
   
    /** Returns an array containing all the usergroup's user entities.*/
    public UserEntity[] getUserEntities() {
      UserEntity[] dummy = {};  
      return (UserEntity[]) userentities.toArray(dummy); 
    }
    
    /** Method that given an array of available directories returns which isn't already
     * in use by the rule set. */
    public String[] nonUsedDirectories(String[] availabledirectories){
      Vector nonuseddirectories = new Vector(); 
      String[] dummy = {};
      String[] hiddendirectories = GlobalConfiguration.getHiddenDirectories();
      int result;
      boolean hidden=false;
      if(availabledirectories != null){
        for( int i=0; i < availabledirectories.length;i++){
          hidden=false;
          for(int j=0; j < hiddendirectories.length; j++){
             if(availabledirectories[i].startsWith(hiddendirectories[j]))
               hidden=true;  
          }
          if(!hidden){
            result=java.util.Collections.binarySearch(accessrules,new AccessRule(availabledirectories[i],0,false));
            if(result < 0){
              // Directory isn't in use.
              nonuseddirectories.addElement(availabledirectories[i]);
            }
          }
        }
      }
      return  (String[]) nonuseddirectories.toArray(dummy);  
    }
    // Private methods
    
    // Private fields
    private Vector accessrules;
    private Vector userentities;
 }
