package se.anatom.ejbca.ra.authorization;

import java.rmi.*;
import java.io.*;
import java.math.BigInteger;
import java.util.Date;
import java.util.Vector;
import java.util.Collection;
import java.util.TreeMap;
import java.util.Set;
import java.util.Iterator;
import java.sql.*;
import javax.sql.DataSource;
import javax.naming.*;
import javax.rmi.*;
import javax.ejb.*;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.GlobalConfiguration;

/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalAuthorizationSessionBean.java,v 1.5 2002-08-27 12:41:02 herrvendil Exp $
 */
public class LocalAuthorizationSessionBean extends BaseSessionBean  {

    /** Var holding JNDI name of datasource */
    private String dataSource = "java:/DefaultDS";

    /** The home interface of  AvailableAccessRulesData entity bean */
    private AvailableAccessRulesDataLocalHome availableaccessruleshome = null;
    private UserGroupDataLocalHome usergrouphome = null;
    
    private EjbcaAuthorization authorization = null;
    
    private String profileprefix = null;

    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        try{   
          dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);  
          debug("DataSource=" + dataSource); 
          availableaccessruleshome = (AvailableAccessRulesDataLocalHome)lookup("java:comp/env/ejb/AvailableAccessRulesDataLocal");
          usergrouphome = (UserGroupDataLocalHome)lookup("java:comp/env/ejb/UserGroupDataLocal");
        }catch(Exception e){
           throw new CreateException(e.getMessage());   
        }
       debug("<ejbCreate()");
    }
    
    /** Initializes the statful session bean. */
    public void init(GlobalConfiguration globalconfiguration){        
        // Check if usergroup table is empty, if so insert default superuser.
       try{
         Collection result = usergrouphome.findAll();
         if(result.size()==0){
          // Authorization table is empty, fill with default and special usergroups.
           System.out.println("Filling in Default authorization data.");
           UserGroupDataLocal ugdl = usergrouphome.create("Default");
           ugdl.addUserEntity(UserEntity.WITH_COMMONNAME,UserEntity.TYPE_EQUALCASEINS,"Walter");
           ugdl.addAccessRule("/",AccessRule.RULE_ACCEPT,true);
           
           ugdl = usergrouphome.create(UserGroup.SPECIALUSERGROUP_COMMONWEBUSER);
           ugdl.addUserEntity(0,UserEntity.SPECIALUSER_COMMONWEBUSER,"");
           ugdl.addAccessRule("/",AccessRule.RULE_DECLINE,true);   // Temporate
           
           ugdl = usergrouphome.create(UserGroup.SPECIALUSERGROUP_CACOMMANDLINEADMIN);
           ugdl.addUserEntity(0,UserEntity.SPECIALUSER_CACOMMANDLINEADMIN,"");
           ugdl.addAccessRule("/",AccessRule.RULE_ACCEPT,true);          
           
           ugdl = usergrouphome.create(UserGroup.SPECIALUSERGROUP_RACOMMANDLINEADMIN);
           ugdl.addUserEntity(0,UserEntity.SPECIALUSER_RACOMMANDLINEADMIN,"");
           ugdl.addAccessRule("/",AccessRule.RULE_ACCEPT,true); 
           
         }
       }catch(FinderException e){

       }catch(CreateException e){
           throw new EJBException(e.getMessage());             
       }
       
       try{
          authorization = new EjbcaAuthorization(getUserGroups(),globalconfiguration); 
       }catch(NullPointerException f){
       }catch(Exception e){
           throw new EJBException(e.getMessage());   
       }       
       this.profileprefix = globalconfiguration.getProfilePrefix();
    }    

    // Methods used with UserGroupData Entity Beans
    
     /** 
     * Method to check if a user is authorized to a certain resource.
     *
     * @param userinformation can be a certificate or special user, see UserInformation class.
     * 
     */
    public boolean isAuthorized(UserInformation userinformation, String resource) throws  AuthorizationDeniedException{
      return authorization.isAuthorized(userinformation, resource);  
    }
    
    /** 
     * Method to validate, verify and check revokation of a users certificate.
     *
     * @param certificate the users X509Certificate.
     * 
     */
    
    public void authenticate(X509Certificate certificate) throws AuthenticationFailedException{    
     authorization.authenticate(certificate);
    }

   /**
    * Method to add an usergroup.
    *
    * @return  False if usergroup already exists
    */
    public boolean addUserGroup(String usergroupname){
      boolean returnval=true;
      try{
        usergrouphome.findByPrimaryKey(usergroupname);
        returnval=false;
      }catch(FinderException e){
      }
      if(returnval){
        try{
          usergrouphome.create(usergroupname);
          returnval=true;
        }catch(CreateException e){
           returnval=false;
        }
      }
      return returnval;
    } // addUserGroup

    /**
     * Method to remove a usergroup.
     */
    public void removeUserGroup(String usergroupname){
      try{
         UserGroupDataLocal ugl = usergrouphome.findByPrimaryKey(usergroupname);          
        // Remove groups user entities.
         UserEntity[] userentities = ugl.getUserEntitiesAsArray();      
         for(int i=0; i < userentities.length;i++){
           ugl.removeUserEntity(userentities[i].getMatchWith(),userentities[i].getMatchType(), userentities[i].getMatchValue());
         }
        // Remove groups accessrules.  
         AccessRule[] accessrules = ugl.getAccessRulesAsArray();          
         for(int i=0; i < accessrules.length;i++){
           ugl.removeAccessRule(accessrules[i].getDirectory());
         }         
         
         ugl.remove();
      }catch(Exception e){}
    } // removeUserGroup

    /**
     * Metod to rename a usergroup
     *
     * @return false if new usergroup already exists.
     */
    public boolean renameUserGroup(String oldname, String newname){
      boolean returnval = false;
      UserGroupDataLocal ugl = null;
      try{
        ugl = usergrouphome.findByPrimaryKey(newname);
      }catch(FinderException e){
        returnval = true;
      }
      if(returnval){
        try{
          ugl =  usergrouphome.findByPrimaryKey(oldname);
          AccessRule[] accessrules = ugl.getAccessRulesAsArray();
          UserEntity[] userentities = ugl.getUserEntitiesAsArray();
          UserGroupDataLocal newugl = usergrouphome.create(newname);
          newugl.addAccessRules(accessrules);
          newugl.addUserEntities(userentities);
          removeUserGroup(oldname);
        }catch(Exception e){
          returnval=false;
        }
      }
      return returnval;
    } // renameUserGroup


    /**
     * Method to get a reference to a usergroup.
     */

    public UserGroup getUserGroup(String usergroupname){
      UserGroup returnval = null;
      try{
        returnval= (usergrouphome.findByPrimaryKey(usergroupname)).getUserGroup();
      }catch(Exception e){}
      return returnval;
    } // getUserGroup

    /**
     * Returns the number of usergroups
     */
    public int getNumberOfUserGroups(){
      int returnval=0;
      try{
        returnval =  usergrouphome.findAll().size();
      }catch(FinderException e){}

      return returnval;
    } // getNumberOfUserGroups

    /**
     *Returns an array containing all the usergroups names.
     */
     public String[] getUserGroupnames(){
       TreeMap treemap = new TreeMap();
       String[] returnval = null;
       try{
         Collection result = usergrouphome.findAll();
         Iterator i = result.iterator();
         String[] dummy={};

         while(i.hasNext()){
            UserGroupDataLocal ugdl = (UserGroupDataLocal) i.next();
            treemap.put(ugdl.getUserGroupName(),null);
         }
         returnval =  (String[]) treemap.keySet().toArray(dummy);
       }catch(FinderException e){}
       return returnval;
     } // getUserGroupnames

    /**
     * Returns an array containing all the usergroups.
     */
    public UserGroup[] getUserGroups(){
       TreeMap treemap = new TreeMap();
       UserGroup[] returnval= null;
       try{
         Collection result = usergrouphome.findAll();
         Iterator i = result.iterator();
         UserGroup[] dummy={};

         while(i.hasNext()){
            UserGroupDataLocal ugdl = (UserGroupDataLocal) i.next();
            treemap.put(ugdl.getUserGroupName(),ugdl.getUserGroup());
         }
         returnval = (UserGroup[]) treemap.values().toArray(dummy);
       } catch(FinderException e){}
       return returnval;
    } // getUserGroups

     /**
     * Removes an accessrule from the usergroup.
     *
     */

    public void addAccessRule(String usergroupname, String directory, int rule, boolean recursive){
      try{
        (usergrouphome.findByPrimaryKey(usergroupname)).addAccessRule(directory,rule,recursive);
        authorization.buildAccessTree(getUserGroups());       
      }catch(FinderException e){}
    } // addAccessRule


     /**
     * Removes an accessrule from the database.
     *
     */
    public void removeAccessRule(String usergroupname, String directory){
      try{
        (usergrouphome.findByPrimaryKey(usergroupname)).removeAccessRule(directory);
        authorization.buildAccessTree(getUserGroups());
      }catch(FinderException e){}
    } // removeAccessRule

     /**
     * Returns the number of access rules in usergroup
     *
     * @return the number of accessrules in the usergroup
     */
    public int getNumberOfAccessRules(String usergroupname){
      int returnval=0;
      try{
        returnval=(usergrouphome.findByPrimaryKey(usergroupname)).getNumberOfAccessRules();
      }catch(FinderException e){}
      return returnval;
    } // getNumberOfAccessRules

     /**
      * Returns all the accessrules in the usergroup as an array of AccessRule
      *
      */
    public AccessRule[] getAccessRules(String usergroupname){
      AccessRule[] returnval=null;
      try{
        returnval=(usergrouphome.findByPrimaryKey(usergroupname)).getAccessRulesAsArray();
        authorization.buildAccessTree(getUserGroups());
      }catch(FinderException e){}

      return returnval;
    } // getAccessRules

     /**
     * Adds a user entity to the usergroup. Changes it's values if it already exists
     *
     */

    public void addUserEntity(String usergroupname, int matchwith, int matchtype, String matchvalue){  
      try{
        (usergrouphome.findByPrimaryKey(usergroupname)).addUserEntity(matchwith, matchtype, matchvalue);
        authorization.buildAccessTree(getUserGroups());
      }catch(FinderException e){}
    } // addUserEntity


     /**
     * Removes a user entity from the usergroup.
     *
     */
    public void removeUserEntity(String usergroupname, int matchwith, int matchtype, String matchvalue){
      try{
        (usergrouphome.findByPrimaryKey(usergroupname)).removeUserEntity(matchwith, matchtype, matchvalue);
        authorization.buildAccessTree(getUserGroups());
      }catch(FinderException e){}
    } // removeUserEntity

     /**
     * Returns the number of user entities in usergroup
     *
     * @return the number of user entities in the database for the specified group
     */
    public int getNumberOfUserEntities(String usergroupname){
      int returnval=0;
      try{
        returnval = (usergrouphome.findByPrimaryKey(usergroupname)).getNumberOfUserEntities();
      }catch(FinderException e){}

      return returnval;
    } // getNumberOfUserEntities

     /**
      * Returns all the UserEntities as an array of UserEntities for the specified group.
      *
      */
    public UserEntity[] getUserEntities(String usergroupname){
      UserEntity[] returnval = null;
      try{
        returnval = (usergrouphome.findByPrimaryKey(usergroupname)).getUserEntitiesAsArray();
      }catch(FinderException e){}
      return returnval;
    } // getUserEntities

    // Methods used with AvailableAccessRulesData Entity beans.

    /**
     * Method to add an access rule.
     */

    public void addAvailableAccessRule(String name){
        debug(">addAvailableAccessRule(name : " + name + ")");
        try {
            AvailableAccessRulesDataLocal data= availableaccessruleshome.create(name);         
        }
        catch (Exception e) {
        }
        debug("<addAvailableAccessRule");
    } // addAvailableAccessRule

    /**
     * Method to add an Collection of access rules.
     */

    public void addAvailableAccessRules(Collection names){
        debug(">addAvailableAccessRules(size : " + names.size() + ")");
        if(names != null){
          Iterator i = names.iterator();
          while(i.hasNext()){
            String name = (String) i.next();

            try {
              AvailableAccessRulesDataLocal data= availableaccessruleshome.create(name);
            }
            catch (Exception e) {
            }
          }
        }
        debug("<addAvailableAccessRules");
    } //  addAvailableAccessRules

    /**
     * Method to remove an access rule.
     */

    public void removeAvailableAccessRule(String name){
      debug(">removeAvailableAccessRule(name : " + name + ")");
      try{
        AvailableAccessRulesDataLocal data= availableaccessruleshome.findByPrimaryKey(name);
        data.remove();
      }catch(Exception e){

      }
      debug("<removeAvailableAccessRule");
    } // removeAvailableAccessRule

    /**
     * Method to remove an Collection of access rules.
     */

    public void removeAvailableAccessRules(Collection names){
      debug(">removeAvailableAccessRules(size : " + names.size() + ")");
        if(names != null){
          Iterator i = names.iterator();
          while(i.hasNext()){
            String name = (String) i.next();

            try{
              AvailableAccessRulesDataLocal data= availableaccessruleshome.findByPrimaryKey(name);
              data.remove();
            }catch(Exception e){
            }
          }
        }
        debug("<removeAvailableAccessRules");
    } // removeAvailableAccessRules

    /**
     * Method that returns a Collection of Strings containing all access rules.
     */

    public Collection getAvailableAccessRules(){
       Vector returnval = new Vector();
       Collection result = null;
       try{
         result = availableaccessruleshome.findAll();
       }catch(Exception e){
       }
       if(result != null){
         Iterator i = result.iterator();
         while(i.hasNext()){
           AvailableAccessRulesDataLocal data =  (AvailableAccessRulesDataLocal) i.next();
           returnval.addElement(data.getName());
         }
       }
       java.util.Collections.sort(returnval);
       return returnval;
    } // getAvailableAccessRules

    /**
     * Checks wheither an access rule exists in the database.
     */

    public boolean existsAvailableAccessRule(String name){
       boolean returnval = false;
       try{
         availableaccessruleshome.findByPrimaryKey(name);
         returnval=true;
       }catch(FinderException e){
          returnval = false;
       }
       return returnval;
    } // existsAvailableAccessRule

    /** 
     * Method to check if a profile exists in any profile rules. Used to avoid desyncronization of profilerules.
     *
     * @param profileid the profile id to search for.
     * @return true if profile exists in any of the accessrules.
     */
    
    public boolean existsProfileInRules(int profileid){
       boolean exists = false;
       String profilestring= this.profileprefix + Integer.toString(profileid);
       try{
         Collection result = usergrouphome.findAll();
         Iterator i = result.iterator();
         AccessRule[] accessrules = null; 
         
         while(i.hasNext() && !exists){
            UserGroupDataLocal ugdl = (UserGroupDataLocal) i.next();
            accessrules=ugdl.getAccessRulesAsArray();
            for(int j=0; j < accessrules.length; j++){
               exists = accessrules[j].getDirectory().startsWith(profilestring);
               if(exists)
                 break;  
            }
         }
       } catch(FinderException e){}        
       
       return exists;   
    }


} // LocalAvailableAccessRulesDataBean

