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
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.LogEntry;
/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalAuthorizationSessionBean.java,v 1.8 2002-10-24 20:06:55 herrvendil Exp $
 */
public class LocalAuthorizationSessionBean extends BaseSessionBean  {

    /** Var holding JNDI name of datasource */
    private String dataSource = "java:/DefaultDS";

    /** The home interface of  AvailableAccessRulesData entity bean */
    private AvailableAccessRulesDataLocalHome availableaccessruleshome = null;
    /** The home interface of  AdminGroupData entity bean */    
    private AdminGroupDataLocalHome admingrouphome = null;

    /** The remote interface of  log session bean */    
    private ILogSessionRemote logsession = null;
    
    private EjbcaAuthorization authorization = null;
    
    private String profileprefix = null;
    
    /** Var containing information about administrator using the bean.*/
    private Admin admin = null;
   

    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate(GlobalConfiguration globalconfiguration, Admin administrator) throws CreateException {
        debug(">ejbCreate()");
        try{   
          dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);  
          debug("DataSource=" + dataSource); 
          availableaccessruleshome = (AvailableAccessRulesDataLocalHome)lookup("java:comp/env/ejb/AvailableAccessRulesDataLocal");
          admingrouphome = (AdminGroupDataLocalHome)lookup("java:comp/env/ejb/AdminGroupDataLocal");
          
           this.admin = administrator;
           ILogSessionHome logsessionhome = (ILogSessionHome) lookup("java:comp/env/ejb/LogSession",ILogSessionHome.class);       
           logsession = logsessionhome.create();
        }catch(Exception e){
           throw new CreateException(e.getMessage());   
        }
        // Check if admingroup table is empty, if so insert default superuser.
       try{
         Collection result = admingrouphome.findAll();
         if(result.size()==0){
          // Authorization table is empty, fill with default and special admingroups.
           AdminGroupDataLocal ugdl = admingrouphome.create("Default");
           ugdl.addAdminEntity(AdminEntity.WITH_COMMONNAME,AdminEntity.TYPE_EQUALCASEINS,"Walter");
           ugdl.addAccessRule("/",AccessRule.RULE_ACCEPT,true);
           
           ugdl = admingrouphome.create(AdminGroup.SPECIALADMINGROUP_PUBLICWEBADMIN);
           ugdl.addAdminEntity(0,AdminEntity.SPECIALADMIN_PUBLICWEBUSER,"");
           ugdl.addAccessRule("/",AccessRule.RULE_DECLINE,true);   // Temporate
           
           ugdl = admingrouphome.create(AdminGroup.SPECIALADMINGROUP_CACOMMANDLINEADMIN);
           ugdl.addAdminEntity(0,AdminEntity.SPECIALADMIN_CACOMMANDLINEADMIN,"");
           ugdl.addAccessRule("/",AccessRule.RULE_ACCEPT,true);          
           
           ugdl = admingrouphome.create(AdminGroup.SPECIALADMINGROUP_RACOMMANDLINEADMIN);
           ugdl.addAdminEntity(0,AdminEntity.SPECIALADMIN_RACOMMANDLINEADMIN,"");
           ugdl.addAccessRule("/",AccessRule.RULE_ACCEPT,true); 
           
           ugdl = admingrouphome.create(AdminGroup.SPECIALADMINGROUP_BATCHCOMMANDLINEADMIN);
           ugdl.addAdminEntity(0,AdminEntity.SPECIALADMIN_BATCHCOMMANDLINEADMIN,"");
           ugdl.addAccessRule("/",AccessRule.RULE_ACCEPT,true);            
           
         }
       }catch(FinderException e){

       }catch(CreateException e){
           throw new EJBException(e.getMessage());             
       }
       
       try{
          authorization = new EjbcaAuthorization(getAdminGroups(),globalconfiguration, logsession, admin, LogEntry.MODULE_RA); 
       }catch(NullPointerException f){
       }catch(Exception e){
           throw new EJBException(e.getMessage());   
       }       
       this.profileprefix = globalconfiguration.ENDENTITYPROFILEPREFIX;        
                
       debug("<ejbCreate()");
    }


    // Methods used with AdminGroupData Entity Beans
    
     /** 
     * Method to check if a user is authorized to a certain resource.
     *
     * @param admininformation can be a certificate or special user, see AdminInformation class.
     * 
     */
    public boolean isAuthorized(AdminInformation admininformation, String resource) throws  AuthorizationDeniedException{
      return authorization.isAuthorized(admininformation, resource);  
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
    * Method to add an admingroup.
    *
    * @return  False if admingroup already exists
    */
    public boolean addAdminGroup(String admingroupname){
      boolean returnval=true;
      try{
        admingrouphome.findByPrimaryKey(admingroupname);
        returnval=false;
      }catch(FinderException e){
      }
      if(returnval){
        try{
          admingrouphome.create(admingroupname);
          returnval=true;
        }catch(CreateException e){
           returnval=false;
        }
      }
      
      try{
        if(returnval)
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Administratorgroup " + admingroupname + " added.");            
        else
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error adding administratorgroup "  + admingroupname + ".");      
      }catch( RemoteException re){}
      
      return returnval;
    } // addAdminGroup

    /**
     * Method to remove a admingroup.
     */
    public void removeAdminGroup(String admingroupname){
      try{
         AdminGroupDataLocal ugl = admingrouphome.findByPrimaryKey(admingroupname);          
        // Remove groups user entities.
         AdminEntity[] adminentities = ugl.getAdminEntitiesAsArray();      
         for(int i=0; i < adminentities.length;i++){
           ugl.removeAdminEntity(adminentities[i].getMatchWith(),adminentities[i].getMatchType(), adminentities[i].getMatchValue());
         }
        // Remove groups accessrules.  
         AccessRule[] accessrules = ugl.getAccessRulesAsArray();          
         for(int i=0; i < accessrules.length;i++){
           ugl.removeAccessRule(accessrules[i].getResource());
         }         
         
         ugl.remove();
         logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Administratorgroup " + admingroupname + " removed.");         
      }catch(Exception e){
         try{
           logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error removing administratorgroup " + admingroupname + ".");      
         }catch(RemoteException re){}
      }
    } // removeAdminGroup

    /**
     * Metod to rename a admingroup
     *
     * @return false if new admingroup already exists.
     */
    public boolean renameAdminGroup(String oldname, String newname){
      boolean returnval = false;
      AdminGroupDataLocal ugl = null;
      try{
        ugl = admingrouphome.findByPrimaryKey(newname);
      }catch(FinderException e){
        returnval = true;
      }
      if(returnval){
        try{
          ugl =  admingrouphome.findByPrimaryKey(oldname);
          AccessRule[] accessrules = ugl.getAccessRulesAsArray();
          AdminEntity[] adminentities = ugl.getAdminEntitiesAsArray();
          AdminGroupDataLocal newugl = admingrouphome.create(newname);
          newugl.addAccessRules(accessrules);
          newugl.addAdminEntities(adminentities);
          removeAdminGroup(oldname);
        }catch(Exception e){
          returnval=false;
        }
      }
      
      try{
        if(returnval)
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Renamed administratorgroup " + oldname + " to " + newname + ".");            
        else
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error renaming administratorgroup " + oldname + " to " + newname + ".");      
      }catch( RemoteException re){}
      
      return returnval;
    } // renameAdminGroup


    /**
     * Method to get a reference to a admingroup.
     */

    public AdminGroup getAdminGroup(String admingroupname){
      AdminGroup returnval = null;
      try{
        returnval= (admingrouphome.findByPrimaryKey(admingroupname)).getAdminGroup();
      }catch(Exception e){}
      return returnval;
    } // getAdminGroup

    /**
     * Returns the number of admingroups
     */
    public int getNumberOfAdminGroups(){
      int returnval=0;
      try{
        returnval =  admingrouphome.findAll().size();
      }catch(FinderException e){}

      return returnval;
    } // getNumberOfAdminGroups

    /**
     *Returns an array containing all the admingroups names.
     */
     public String[] getAdminGroupnames(){
       TreeMap treemap = new TreeMap();
       String[] returnval = null;
       try{
         Collection result = admingrouphome.findAll();
         Iterator i = result.iterator();
         String[] dummy={};

         while(i.hasNext()){
            AdminGroupDataLocal ugdl = (AdminGroupDataLocal) i.next();
            treemap.put(ugdl.getAdminGroupName(),null);
         }
         returnval =  (String[]) treemap.keySet().toArray(dummy);
       }catch(FinderException e){}
       return returnval;
     } // getAdminGroupnames

    /**
     * Returns an array containing all the admingroups.
     */
    public AdminGroup[] getAdminGroups(){
       TreeMap treemap = new TreeMap();
       AdminGroup[] returnval= null;
       try{
         Collection result = admingrouphome.findAll();
         Iterator i = result.iterator();
         AdminGroup[] dummy={};

         while(i.hasNext()){
            AdminGroupDataLocal ugdl = (AdminGroupDataLocal) i.next();
            treemap.put(ugdl.getAdminGroupName(),ugdl.getAdminGroup());
         }
         returnval = (AdminGroup[]) treemap.values().toArray(dummy);
       } catch(FinderException e){}
       return returnval;
    } // getAdminGroups

     /**
     * Removes an accessrule from the admingroup.
     *
     */

    public void addAccessRule(String admingroupname, String resource, int rule, boolean recursive){
      String logrule = " accept ";
      if(rule == AccessRule.RULE_DECLINE)
        logrule = " decline ";
      if(recursive)
         logrule = logrule + " recursive"; 
      try{
        (admingrouphome.findByPrimaryKey(admingroupname)).addAccessRule(resource,rule,recursive);
        authorization.buildAccessTree(getAdminGroups());       
        logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Added accessrule : " + resource + logrule + " to administratorgroup " + admingroupname + ".");
      }catch(Exception e){
        try{  
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error adding accessrule : " + resource + logrule + " to administratorgroup " + admingroupname + "."); 
        }catch( RemoteException re){}        
      }
    } // addAccessRule


     /**
     * Removes an accessrule from the database.
     *
     */
    public void removeAccessRule(String admingroupname, String resource){
      try{
        (admingrouphome.findByPrimaryKey(admingroupname)).removeAccessRule(resource);
        authorization.buildAccessTree(getAdminGroups());
        logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Removed accessrule : " + resource + " from administratorgroup " + admingroupname + ".");        
      }catch(Exception e){
        try{  
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Error removing accessrule : " + resource + " from administratorgroup " + admingroupname + ".");    
        }catch( RemoteException re){}        
      }
    } // removeAccessRule

     /**
     * Returns the number of access rules in admingroup
     *
     * @return the number of accessrules in the admingroup
     */
    public int getNumberOfAccessRules(String admingroupname){
      int returnval=0;
      try{
        returnval=(admingrouphome.findByPrimaryKey(admingroupname)).getNumberOfAccessRules();
      }catch(FinderException e){}
      return returnval;
    } // getNumberOfAccessRules

     /**
      * Returns all the accessrules in the admingroup as an array of AccessRule
      *
      */
    public AccessRule[] getAccessRules(String admingroupname){
      AccessRule[] returnval=null;
      try{
        returnval=(admingrouphome.findByPrimaryKey(admingroupname)).getAccessRulesAsArray();
        authorization.buildAccessTree(getAdminGroups());
      }catch(FinderException e){}

      return returnval;
    } // getAccessRules

     /**
     * Adds a user entity to the admingroup. Changes it's values if it already exists
     *
     */

    public void addAdminEntity(String admingroupname, int matchwith, int matchtype, String matchvalue){         
      try{
        (admingrouphome.findByPrimaryKey(admingroupname)).addAdminEntity(matchwith, matchtype, matchvalue);
        authorization.buildAccessTree(getAdminGroups());
        logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Added administrator entity " + matchvalue + " to administratorgroup " + admingroupname + ".");        
      }catch(Exception e){
        try{  
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error adding administrator entity " + matchvalue + " to administratorgroup " + admingroupname + ".");  
        }catch( RemoteException re){}        
      }
    } // addAdminEntity


     /**
     * Removes a user entity from the admingroup.
     *
     */
    public void removeAdminEntity(String admingroupname, int matchwith, int matchtype, String matchvalue){
      try{
        (admingrouphome.findByPrimaryKey(admingroupname)).removeAdminEntity(matchwith, matchtype, matchvalue);
        authorization.buildAccessTree(getAdminGroups());
        logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Removed administrator entity " + matchvalue + " from administratorgroup " + admingroupname + ".");        
      }catch(Exception e){
        try{  
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error removing administrator entity " + matchvalue + " from administratorgroup " + admingroupname + ".");  
        }catch( RemoteException re){}        
      }
    } // removeAdminEntity

     /**
     * Returns the number of user entities in admingroup
     *
     * @return the number of user entities in the database for the specified group
     */
    public int getNumberOfAdminEntities(String admingroupname){
      int returnval=0;
      try{
        returnval = (admingrouphome.findByPrimaryKey(admingroupname)).getNumberOfAdminEntities();
      }catch(FinderException e){}

      return returnval;
    } // getNumberOfAdminEntities

     /**
      * Returns all the AdminEntities as an array of AdminEntities for the specified group.
      *
      */
    public AdminEntity[] getAdminEntities(String admingroupname){
      AdminEntity[] returnval = null;
      try{
        returnval = (admingrouphome.findByPrimaryKey(admingroupname)).getAdminEntitiesAsArray();
      }catch(FinderException e){}
      return returnval;
    } // getAdminEntities

    // Methods used with AvailableAccessRulesData Entity beans.

    /**
     * Method to add an access rule.
     */

    public void addAvailableAccessRule(String name){
        debug(">addAvailableAccessRule(name : " + name + ")");
        try {
            AvailableAccessRulesDataLocal data= availableaccessruleshome.create(name);      
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Adding available access rule" + name + ".");              
        }
        catch (Exception e) {
          try{    
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error adding available access rule" + name + ".");  
          }catch( RemoteException re){}  
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
              logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Added available access rule" + name + ".");              
            }
            catch (Exception e) {
              try{  
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error adding available access rule" + name + ".");                
              }catch( RemoteException re){}  
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
        logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Removed available access rule" + name + ".");          
      }catch(Exception e){
        try{  
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error removing available access rule " + name + ".");  
        }catch( RemoteException re){}  
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
              logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Removed available access rule" + name + ".");                
            }catch(Exception e){
              try{  
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error removing available access rule " + name + ".");
              }catch( RemoteException re){}  
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
     * Method to check if an end entity profile exists in any end entity profile rules. Used to avoid desyncronization of profilerules.
     *
     * @param profileid the profile id to search for.
     * @return true if profile exists in any of the accessrules.
     */
    
    public boolean existsEndEntityProfileInRules(int profileid){
       boolean exists = false;
       String profilestring= this.profileprefix + Integer.toString(profileid);
       try{
         Collection result = admingrouphome.findAll();
         Iterator i = result.iterator();
         AccessRule[] accessrules = null; 
         
         while(i.hasNext() && !exists){
            AdminGroupDataLocal ugdl = (AdminGroupDataLocal) i.next();
            accessrules=ugdl.getAccessRulesAsArray();
            for(int j=0; j < accessrules.length; j++){
               exists = accessrules[j].getResource().startsWith(profilestring);
               if(exists)
                 break;  
            }
         }
       } catch(FinderException e){}        
       
       return exists;   
    }


} // LocalAvailableAccessRulesDataBean

