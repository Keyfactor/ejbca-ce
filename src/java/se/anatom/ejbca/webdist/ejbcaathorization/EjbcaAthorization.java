/*
 * EjbcaAthorization.java
 *
 * Created on den 23 mars 2002, 17:34
 */

package se.anatom.ejbca.webdist.ejbcaathorization;

import java.beans.*;
import java.security.cert.X509Certificate;
import java.io.IOException;

import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;

/**
 * A java bean handling the athorization to JSP pages.
 * 
 * The main metod are isAthorized.
 *
 * @author  Philip Vendil
 */
public class EjbcaAthorization extends Object implements java.io.Serializable {
    // Public constants.
    public static final int ACCESS_RULE_DIRECTORY = 0;
    public static final int ACCESS_RULE_RULE      = 1;
    public static final int ACCESS_RULE_RECURSIVE = 2;

    public static final int USER_ENTITY_MATCHWITH  = 0;
    public static final int USER_ENTITY_MATCHTYPE  = 1;
    public static final int USER_ENTITY_MATCHVALUE = 2;
    

   
    /** Creates new EjbcaAthorization */
    public EjbcaAthorization(GlobalConfiguration globalconfiguration) {
        this.globalconfiguration = globalconfiguration;        
        getParameters();
        accesstree = new AccessTree(baseurl, usergroups, opendirectories);
        availabledirectories = new AvailableDirectories(documentroot,hiddendirectories,globalconfiguration.getRaAdminPath());
        usergroupsdatahandler = new UserGroupsDataHandler();
        loadAccessData();
    }
    
    // Public methods.
    
    /** EjbcaAthorization beans main method. Checks if a user have access to a specific url. */
    public boolean isAthorized(X509Certificate certificate, String url) throws AuthorizationDeniedException {
        // Check in accesstree.
        if(accesstree.isAthorized(certificate, url) == false)
          throw  new AuthorizationDeniedException();  
        return true;
    }
    
    
    /** Method to add a new usergroup to the access control data.*/
    public void addUserGroup(String name) throws UsergroupExistsException{
        usergroups.addUserGroup(name,new UserGroup());
        saveAccessData();
    }

    /** Method to remove a usergroup.*/
    public void removeUserGroup(String name){
        usergroups.removeUserGroup(name);
        saveAccessData();
    }
    
    /** Method to rename a usergroup. */
    public void renameUserGroup(String oldname, String newname) throws UsergroupExistsException{
      usergroups.renameUserGroup(oldname, newname);        
      saveAccessData();  
    }
    
    /** Method to retrieve all usergroup's names.*/
    public String[] getUserGroupnames(){
        return usergroups.getUserGroupnames();
    }
    
    /** Method to add an array of access rules to a usergroup. The accessrules must be a 2d array where
     *  the outer array specifies the field using ACCESS_RULE constants. */
    public void addAccessRules(String groupname, String[][] accessrules){
        int arraysize = accessrules.length;
        try{
          for(int i=0; i < arraysize; i++){
            usergroups.getUserGroup(groupname).addAccessRule(accessrules[i][ACCESS_RULE_DIRECTORY],
                                java.lang.Integer.valueOf(accessrules[i][ACCESS_RULE_RULE]).intValue(),
                                java.lang.Boolean.valueOf(accessrules[i][ACCESS_RULE_RECURSIVE]).booleanValue());
          }
        }catch (Exception e){
            // Do not add erronios rules.
        }
        saveAccessData();
    }
    
    /** Method to remove an array of access rules from a usergroup.*/
    public void removeAccessRules(String groupname, String[][] accessrules){
        int arraysize = accessrules.length;
        try{
          for(int i=0; i < arraysize; i++){
            usergroups.getUserGroup(groupname).removeAccessRule(accessrules[i][ACCESS_RULE_DIRECTORY]);
          }
        }catch (Exception e){
            // Do not add erronios rules.
        }
        saveAccessData();
        
    }
   
    /** Method that returns all access rules applied to a group.*/
    public String[][] getAccessRules(String groupname){
        AccessRule[] accessrules = null;
        String[][]   returnarray = null;
        
        accessrules=usergroups.getUserGroup(groupname).getAccessRules();
        if(accessrules != null){
          returnarray = new String[accessrules.length][3];
          for(int i = 0; i < accessrules.length; i++){
             returnarray[i][ACCESS_RULE_DIRECTORY] = accessrules[i].getDirectory();
             returnarray[i][ACCESS_RULE_RULE] = String.valueOf(accessrules[i].getRule());
             returnarray[i][ACCESS_RULE_RECURSIVE] = String.valueOf(accessrules[i].isRecursive());
          }
        }
        return returnarray;
    }
    
    /** Method that returns all avaliable rules to a usergroup. It checks the filesystem for
     * all directories beneaf document root that isn't set hidden or already applied to this group.*/
    public String[] getAvailableRules(String groupname) throws IOException{  
      return usergroups.getUserGroup(groupname).nonUsedDirectories(availabledirectories.getDirectories(), hiddendirectories);
    }
    
      /** Method to add an array of user entities  to a usergroup. A user entity
       *  van be a single user or an entire organization depending on how it's match 
       *  rules i set. The userentities must be a 2d array where
       *  the outer array specifies the fields using USER_ENTITY constants.*/
    public void addUserEntities(String groupname, String[][] userentities){
       int arraysize = userentities.length;
        try{
          for(int i=0; i < arraysize; i++){
            usergroups.getUserGroup(groupname).addUserEntity(
                                Integer.parseInt(userentities[i][USER_ENTITY_MATCHWITH]),
                                Integer.parseInt(userentities[i][USER_ENTITY_MATCHTYPE]),
                                userentities[i][USER_ENTITY_MATCHVALUE]);
          }
       }catch (Exception e){
            // Do not add erronios rules.
       }
       saveAccessData();
    }
    
        /** Method to remove an array of user entities from a usergroup.*/
    public void removeUserEntities(String groupname, String[][] userentities){
      int arraysize = userentities.length;
      try{
        for(int i=0; i < arraysize; i++){
           usergroups.getUserGroup(groupname).removeUserEntity(Integer.parseInt(userentities[i][USER_ENTITY_MATCHWITH])
                                                               ,Integer.parseInt(userentities[i][USER_ENTITY_MATCHTYPE])
                                                               ,userentities[i][USER_ENTITY_MATCHVALUE]);
        }
      }catch (Exception e){
        // Do not remove erronios rules.
      }
      saveAccessData();
    }
    
    /** Method that returns all user entities belonging to a group.*/
    public String[][] getUserEntities(String groupname){
      UserEntity[] userentities;
      String[][]   returnarray;
        
      userentities=usergroups.getUserGroup(groupname).getUserEntities();
      returnarray = new String[userentities.length][3];
      for(int i = 0; i < userentities.length; i++){
        returnarray[i][USER_ENTITY_MATCHWITH] = String.valueOf(userentities[i].getMatchWith());
        returnarray[i][USER_ENTITY_MATCHTYPE] = String.valueOf(userentities[i].getMatchType());
        returnarray[i][USER_ENTITY_MATCHVALUE] = userentities[i].getMatchValue();
      }
      return returnarray;  
    }
    
    // Private metods
    
    /** Method to retrieve parameters from configuration part.*/
    private void getParameters(){
        // Get a copy of global values.
        opendirectories = new String[globalconfiguration .getOpenDirectories().length];
        System.arraycopy(globalconfiguration .getOpenDirectories(),0,opendirectories,0,
                         globalconfiguration .getOpenDirectories().length);
        hiddendirectories = new String[globalconfiguration .getHiddenDirectories().length];
        System.arraycopy(globalconfiguration .getHiddenDirectories(),0,hiddendirectories,0,
                         globalconfiguration .getHiddenDirectories().length);
        baseurl=  new String(globalconfiguration .getBaseUrl());
        documentroot =  new String(globalconfiguration .getDocumentRoot());        
    }
    
     /** Metod to save the access data to the database. */
    private void saveAccessData(){   
      usergroupsdatahandler.saveAccessData(usergroups);
      accesstree.buildTree(usergroups, opendirectories);
    }
    
    /** Metod to load the access data from database. */
    private void loadAccessData(){
      usergroups = usergroupsdatahandler.loadAccessData();
      accesstree.buildTree(usergroups, opendirectories);
    }

    // Private fields.
    
    private String                baseurl;
    private String                documentroot;
    private String[]              opendirectories;
    private String[]              hiddendirectories;
    private UserGroups            usergroups;
    private AccessTree            accesstree;
    private AvailableDirectories  availabledirectories;
    private UserGroupsDataHandler usergroupsdatahandler;
    private GlobalConfiguration   globalconfiguration;    
}
