package se.anatom.ejbca.ra.authorization;

import java.rmi.*;
import java.util.Vector;
import java.util.Collection;
import java.util.TreeMap;
import java.util.Iterator;
import javax.ejb.*;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.LogEntry;
/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalAuthorizationSessionBean.java,v 1.14 2003-03-21 12:27:47 anatom Exp $
 */
public class LocalAuthorizationSessionBean extends BaseSessionBean  {

    /** Var holding JNDI name of datasource */
    private String dataSource = "";

    /** The home interface of  AvailableAccessRulesData entity bean */
    private AvailableAccessRulesDataLocalHome availableaccessruleshome = null;
    /** The home interface of  AdminGroupData entity bean */
    private AdminGroupDataLocalHome admingrouphome = null;

    /** The remote interface of  log session bean */
    private ILogSessionRemote logsession = null;

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
          admingrouphome = (AdminGroupDataLocalHome)lookup("java:comp/env/ejb/AdminGroupDataLocal");

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
           AdminGroupDataLocal ugdl = admingrouphome.create("Temporary Super Administrator Group");
           ugdl.addAdminEntity(AdminEntity.WITH_COMMONNAME,AdminEntity.TYPE_EQUALCASEINS,"SuperAdmin");
           ugdl.addAccessRule("/",AccessRule.RULE_ACCEPT,true);

         }
       }catch(FinderException e){

       }catch(CreateException e){
           error("Can't create LocalAuthorizationSessionBean:", e);
           throw new EJBException(e);
       }

       debug("<ejbCreate()");
    }


    // Methods used with AdminGroupData Entity Beans

    /**
     * Method to initialize authorization bean, must be called directly after creation of bean.
     */
    public void init(GlobalConfiguration globalconfiguration){
       try{
          authorization = new EjbcaAuthorization(getAdminGroups(new Admin(Admin.TYPE_INTERNALUSER)),globalconfiguration, logsession, new Admin(Admin.TYPE_INTERNALUSER), LogEntry.MODULE_RA);
       }catch(NullPointerException f){
       }catch(Exception e){
           error("init:", e);
           throw new EJBException(e);
       }
       this.profileprefix = GlobalConfiguration.ENDENTITYPROFILEPREFIX;
    }


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
     * Method to check if a user is authorized to a certain resource without performing any logging.
     *
     * @param admininformation can be a certificate or special user, see AdminInformation class.
     *
     */
    public boolean isAuthorizedNoLog(AdminInformation admininformation, String resource) throws AuthorizationDeniedException{
      return authorization.isAuthorizedNoLog(admininformation, resource);
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
    public boolean addAdminGroup(Admin admin, String admingroupname){
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
            error("Can't add admingroup:"+e.getMessage());
            returnval=false;
        }
      }

      try{
        if(returnval)
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Administratorgroup " + admingroupname + " added.");
        else
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error adding administratorgroup "  + admingroupname + ".");
      }catch( RemoteException re){
            error("Can't write log: ",re);
      }

      return returnval;
    } // addAdminGroup

    /**
     * Method to remove a admingroup.
     */
    public void removeAdminGroup(Admin admin, String admingroupname){
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
          error("RemoveAdminGroup: "+e);
         try{
           logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error removing administratorgroup " + admingroupname + ".");
         }catch(RemoteException re){
            error("Can't write log: ",re);
         }
      }
    } // removeAdminGroup

    /**
     * Metod to rename a admingroup
     *
     * @return false if new admingroup already exists.
     */
    public boolean renameAdminGroup(Admin admin, String oldname, String newname){
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
          removeAdminGroup(admin, oldname);
        }catch(Exception e){
            error("Can't rename admingroup:"+e.getMessage());
            returnval=false;
        }
      }

      try{
        if(returnval)
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Renamed administratorgroup " + oldname + " to " + newname + ".");
        else
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error renaming administratorgroup " + oldname + " to " + newname + ".");
      }catch( RemoteException re){
          error("Can't write log: ",re);
      }

      return returnval;
    } // renameAdminGroup


    /**
     * Method to get a reference to a admingroup.
     */

    public AdminGroup getAdminGroup(Admin admin, String admingroupname){
      AdminGroup returnval = null;
      try{
        returnval = (admingrouphome.findByPrimaryKey(admingroupname)).getAdminGroup();
      }catch(Exception e){
          error("Can't get admingroup:"+e.getMessage());
      }
      return returnval;
    } // getAdminGroup

    /**
     * Returns the number of admingroups
     */
    public int getNumberOfAdminGroups(Admin admin){
      int returnval=0;
      try{
        returnval =  admingrouphome.findAll().size();
      }catch(FinderException e){}

      return returnval;
    } // getNumberOfAdminGroups

    /**
     *Returns an array containing all the admingroups names.
     */
     public String[] getAdminGroupnames(Admin admin){
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
    public AdminGroup[] getAdminGroups(Admin admin){
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

    public void addAccessRule(Admin admin, String admingroupname, String resource, int rule, boolean recursive){
      String logrule = " accept ";
      if(rule == AccessRule.RULE_DECLINE)
        logrule = " decline ";
      if(recursive)
         logrule = logrule + " recursive";
      try{
        (admingrouphome.findByPrimaryKey(admingroupname)).addAccessRule(resource,rule,recursive);
        authorization.buildAccessTree(getAdminGroups(admin));
        logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Added accessrule : " + resource + logrule + " to administratorgroup " + admingroupname + ".");
      }catch(Exception e){
          error("Can't add access rule:"+e.getMessage());
          try {
              logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error adding accessrule : " + resource + logrule + " to administratorgroup " + admingroupname + ".");
          }catch( RemoteException re){
              error("Can't write log: ",re);
          }
      }
    } // addAccessRule


     /**
     * Removes an accessrule from the database.
     *
     */
    public void removeAccessRule(Admin admin, String admingroupname, String resource){
      try{
        (admingrouphome.findByPrimaryKey(admingroupname)).removeAccessRule(resource);
        authorization.buildAccessTree(getAdminGroups(admin));
        logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Removed accessrule : " + resource + " from administratorgroup " + admingroupname + ".");
      }catch(Exception e){
        try{
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Error removing accessrule : " + resource + " from administratorgroup " + admingroupname + ".");
        }catch( RemoteException re){
            error("Can't write log: ",re);
        }
      }
    } // removeAccessRule

     /**
     * Returns the number of access rules in admingroup
     *
     * @return the number of accessrules in the admingroup
     */
    public int getNumberOfAccessRules(Admin admin, String admingroupname){
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
    public AccessRule[] getAccessRules(Admin admin, String admingroupname){
      AccessRule[] returnval=null;
      try{
        returnval=(admingrouphome.findByPrimaryKey(admingroupname)).getAccessRulesAsArray();
        authorization.buildAccessTree(getAdminGroups(admin));
      }catch(FinderException e){}

      return returnval;
    } // getAccessRules

     /**
     * Adds a user entity to the admingroup. Changes it's values if it already exists
     *
     */

    public void addAdminEntity(Admin admin, String admingroupname, int matchwith, int matchtype, String matchvalue){
      try{
        if(matchwith == AdminEntity.WITH_SERIALNUMBER){
          try{
            matchvalue = new RegularExpression.RE(" ",false).replace(matchvalue,"");
          }catch(Exception e){}
        }

        (admingrouphome.findByPrimaryKey(admingroupname)).addAdminEntity(matchwith, matchtype, matchvalue);
        authorization.buildAccessTree(getAdminGroups(admin));
        logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Added administrator entity " + matchvalue + " to administratorgroup " + admingroupname + ".");
      }catch(Exception e){
          error("Can't add admin entity: ",e);
          try{
              logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error adding administrator entity " + matchvalue + " to administratorgroup " + admingroupname + ".");
          }catch( RemoteException re){
              error("Can't write log: ",re);
          }
      }
    } // addAdminEntity


     /**
     * Removes a user entity from the admingroup.
     *
     */
    public void removeAdminEntity(Admin admin, String admingroupname, int matchwith, int matchtype, String matchvalue){
      try{
        (admingrouphome.findByPrimaryKey(admingroupname)).removeAdminEntity(matchwith, matchtype, matchvalue);
        authorization.buildAccessTree(getAdminGroups(admin));
        logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Removed administrator entity " + matchvalue + " from administratorgroup " + admingroupname + ".");
      }catch(Exception e){
          error("Can't add admin entity: ",e);
          try{
              logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error removing administrator entity " + matchvalue + " from administratorgroup " + admingroupname + ".");
          }catch( RemoteException re){
              error("Can't write log: ",re);
          }
      }
    } // removeAdminEntity

     /**
     * Returns the number of user entities in admingroup
     *
     * @return the number of user entities in the database for the specified group
     */
    public int getNumberOfAdminEntities(Admin admin, String admingroupname){
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
    public AdminEntity[] getAdminEntities(Admin admin, String admingroupname){
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

    public void addAvailableAccessRule(Admin admin, String name){
        debug(">addAvailableAccessRule(name : " + name + ")");
        try {
            AvailableAccessRulesDataLocal data= availableaccessruleshome.create(name);
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Adding available access rule" + name + ".");
        }
        catch (Exception e) {
          error("Can't add available access rule: ",e);
          try{
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error adding available access rule" + name + ".");
          }catch( RemoteException re){
              error("Can't write log: ",re);
          }
        }
        debug("<addAvailableAccessRule");
    } // addAvailableAccessRule

    /**
     * Method to add an Collection of access rules.
     */

    public void addAvailableAccessRules(Admin admin, Collection names){
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
              error("Can't add available access rule: ",e);
              try{
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error adding available access rule" + name + ".");
              }catch( RemoteException re){
                  error("Can't write log: ",re);
              }
            }
          }
        }
        debug("<addAvailableAccessRules");
    } //  addAvailableAccessRules

    /**
     * Method to remove an access rule.
     */

    public void removeAvailableAccessRule(Admin admin, String name){
      debug(">removeAvailableAccessRule(name : " + name + ")");
      try{
        AvailableAccessRulesDataLocal data= availableaccessruleshome.findByPrimaryKey(name);
        data.remove();
        logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Removed available access rule" + name + ".");
      }catch(Exception e){
        error("Can't remove available access rule: ",e);
        try{
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error removing available access rule " + name + ".");
        }catch( RemoteException re){
            error("Can't write log: ",re);
        }
      }
      debug("<removeAvailableAccessRule");
    } // removeAvailableAccessRule

    /**
     * Method to remove an Collection of access rules.
     */

    public void removeAvailableAccessRules(Admin admin, Collection names){
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
              error("Can't remove available access rule: ",e);
              try{
                  logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error removing available access rule " + name + ".");
              }catch( RemoteException re){
                  error("Can't write log: ",re);
              }
            }
          }
        }
        debug("<removeAvailableAccessRules");
    } // removeAvailableAccessRules

    /**
     * Method that returns a Collection of Strings containing all access rules.
     */

    public Collection getAvailableAccessRules(Admin admin){
       Vector returnval = new Vector();
       Collection result = null;
       try{
         result = availableaccessruleshome.findAll();
       }catch(Exception e){
           error("Can't get available access rule: ",e);
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

    public boolean existsAvailableAccessRule(Admin admin, String name){
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

    public boolean existsEndEntityProfileInRules(Admin admin, int profileid){
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

