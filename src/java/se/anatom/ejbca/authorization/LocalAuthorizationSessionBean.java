package se.anatom.ejbca.authorization;

import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.naming.NamingException;
import javax.sql.DataSource;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocalHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocalHome;

/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalAuthorizationSessionBean.java,v 1.2 2003-10-01 11:12:07 herrvendil Exp $
 */
public class LocalAuthorizationSessionBean extends BaseSessionBean  {

    /** Var holding JNDI name of datasource */
    private String dataSource = "";

    /** The home interface of  AdminGroupData entity bean */
    private AdminGroupDataLocalHome admingrouphome = null;

    /** The home interface of AuthorizationTreeUpdateData entity bean */
    private AuthorizationTreeUpdateDataLocalHome authorizationtreeupdatehome = null;
    
    /** help variable used to check that authorization trees is updated. */
    private int authorizationtreeupdate = -1;
    
    /** help variable used to control that update isn't performed to often. */    
    private long lastupdatetime = -1;
    
    /** The local interface of  log session bean */
    private ILogSessionLocal logsession = null;

    /** The local interface of  raadmin session bean */
    private IRaAdminSessionLocal raadminsession = null; 

    /** The local interface of  ca admim session bean */
    private ICAAdminSessionLocal caadminsession = null;    
    
    /** The local interface of certificate store session bean */    
    private ICertificateStoreSessionLocal certificatestoresession = null;
    
    private Authorizer authorizer = null;

    private String[] customaccessrules = null;
    
    private static final String DEFAULTGROUPNAME = "DEFAULT";
    
    
    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        try{
          dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
          debug("DataSource=" + dataSource);
          admingrouphome = (AdminGroupDataLocalHome)lookup("java:comp/env/ejb/AdminGroupDataLocal");
          authorizationtreeupdatehome = (AuthorizationTreeUpdateDataLocalHome)lookup("java:comp/env/ejb/AuthorizationTreeUpdateDataLocal");
          customaccessrules =   ((String) lookup("java:comp/env/CustomAvailableAccessRules", java.lang.String.class)).split(";");
        }catch(Exception e){
           throw new CreateException(e.getMessage());
        }

        try{       
          authorizer = new Authorizer(getAdminGroups(new Admin(Admin.TYPE_INTERNALUSER)),getLogSession(), getCertificateStoreSession(), getRaAdminSession(), getCAAdminSession(), new Admin(Admin.TYPE_INTERNALUSER),LogEntry.MODULE_AUTHORIZATION);
        }catch(Exception e){
           throw new EJBException(e);
        }
        
        debug("<ejbCreate()");
    }


    /** Gets connection to Datasource used for manual SQL searches
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
        return ds.getConnection();
    } //getConnection    
    
    /** Gets connection to log session bean
     * @return Connection
     */
    private ILogSessionLocal getLogSession() {
        if(logsession == null){
          try{
            ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) lookup("java:comp/env/ejb/LogSessionLocal",ILogSessionLocalHome.class);
            logsession = logsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return logsession;
    } //getLogSession

    
    /** Gets connection to certificate store session bean
     * @return Connection
     */
    private IRaAdminSessionLocal getRaAdminSession() {
        if(raadminsession == null){
          try{
            IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) lookup("java:comp/env/ejb/RaAdminSessionLocal",IRaAdminSessionLocalHome.class);
            raadminsession = raadminsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return raadminsession;
    } //getRaAdminSession

    /** Gets connection to certificate store session bean
     * @return ICertificateStoreSessionLocal
     */
    private ICertificateStoreSessionLocal getCertificateStoreSession() {
        if(certificatestoresession == null){
          try{
            ICertificateStoreSessionLocalHome certificatestoresessionhome = (ICertificateStoreSessionLocalHome) lookup("java:comp/env/ejb/CertificateStoreSessionLocal",ICertificateStoreSessionLocalHome.class);
            certificatestoresession = certificatestoresessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return certificatestoresession;
    } //getCertificateStoreSession    


    /** Gets connection to ca admin session bean
     * @return ICAAdminSessionLocal
     */
    private ICAAdminSessionLocal getCAAdminSession() {
        if(caadminsession == null){
          try{
            ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) lookup("java:comp/env/ejb/CAAdminSessionLocal",ICAAdminSessionLocalHome.class);
            caadminsession = caadminsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return caadminsession;
    } //getCAAdminSession        
    
    // Methods used with AdminGroupData Entity Beans

    /**
     * Method to initialize authorization bean, must be called directly after creation of bean. Should only be called once.
     */
    public void initialize(Admin admin, int caid) throws AdminGroupExistsException{
         // Check if admingroup table is empty, if so insert default superuser
         // and create "special edit accessrules count group"
       try{
         Collection result = admingrouphome.findAll();
         if(result.size()==0){
          // Authorization table is empty, fill with default and special admingroups.
           String admingroupname = "Temporary Super Administrator Group";   
           addAdminGroup(admin, admingroupname, caid); 
           ArrayList adminentities = new ArrayList();
           adminentities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME,AdminEntity.TYPE_EQUALCASEINS,"SuperAdmin",caid));
           
           addAdminEntities(admin, admingroupname, caid, adminentities);
           ArrayList accessrules = new ArrayList();
           accessrules.add(new AccessRule("/public_web_user",AccessRule.RULE_ACCEPT,false));
           accessrules.add(new AccessRule("/administrator",AccessRule.RULE_ACCEPT,false));
           accessrules.add(new AccessRule("/super_administrator",AccessRule.RULE_ACCEPT,false));

           accessrules.add(new AccessRule("/ca_functionality",AccessRule.RULE_ACCEPT,true));
           accessrules.add(new AccessRule("/ra_functionality",AccessRule.RULE_ACCEPT,true));
           accessrules.add(new AccessRule("/log_functionality",AccessRule.RULE_ACCEPT,true));
           accessrules.add(new AccessRule("/system_functionality",AccessRule.RULE_ACCEPT,true));
           accessrules.add(new AccessRule("/hardtoken_functionality",AccessRule.RULE_ACCEPT,true));           
           accessrules.add(new AccessRule("/ca",AccessRule.RULE_ACCEPT,true)); 
           accessrules.add(new AccessRule("/endentityprofilesrules",AccessRule.RULE_ACCEPT,true)); 
           
           addAccessRules(admin, admingroupname, caid, accessrules);
           
         }
       }catch(FinderException e){}
         // Add Special Admin Group
       try{
          admingrouphome.findByPrimaryKey(new AdminGroupPK(DEFAULTGROUPNAME, ILogSessionLocal.INTERNALCAID));   
       }catch(FinderException e){
         // Add Default Group
         try{  
           AdminGroupDataLocal agdl = admingrouphome.create(DEFAULTGROUPNAME,  ILogSessionLocal.INTERNALCAID);
        
           ArrayList adminentities = new ArrayList();
           adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_BATCHCOMMANDLINEADMIN));
           adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_CACOMMANDLINEADMIN));   
           adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_RACOMMANDLINEADMIN));  
           adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_INTERNALUSER));
           agdl.addAdminEntities(adminentities);
         
           ArrayList accessrules = new ArrayList();
           accessrules.add(new AccessRule("/administrator",AccessRule.RULE_ACCEPT,true));
           accessrules.add(new AccessRule("/super_administrator",AccessRule.RULE_ACCEPT,false));

           accessrules.add(new AccessRule("/ca_functionality",AccessRule.RULE_ACCEPT,true));
           accessrules.add(new AccessRule("/ra_functionality",AccessRule.RULE_ACCEPT,true));
           accessrules.add(new AccessRule("/log_functionality",AccessRule.RULE_ACCEPT,true));
           accessrules.add(new AccessRule("/system_functionality",AccessRule.RULE_ACCEPT,true));
           accessrules.add(new AccessRule("/hardtoken_functionality",AccessRule.RULE_ACCEPT,true));           
           accessrules.add(new AccessRule("/ca",AccessRule.RULE_ACCEPT,true)); 
           accessrules.add(new AccessRule("/endentityprofilesrules",AccessRule.RULE_ACCEPT,true)); 
          
           agdl.addAccessRules(accessrules);
           
           signalForAuthorizationTreeUpdate();
         }catch(CreateException ce){}
       }
	   // Add Public Web Group
	   this.removeAdminGroup(admin, "Public Web Users",  ILogSessionLocal.INTERNALCAID);
	   try{
		  admingrouphome.findByPrimaryKey(new AdminGroupPK("Public Web Users", ILogSessionLocal.INTERNALCAID));   
	   }catch(FinderException e){	   
	   	 System.out.println("Adding public web group");
	     try{           	   	 
		   AdminGroupDataLocal agdl = admingrouphome.create("Public Web Users",  ILogSessionLocal.INTERNALCAID);
        
		   ArrayList adminentities = new ArrayList();
		   adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_PUBLICWEBUSER));		 
		   agdl.addAdminEntities(adminentities);
         
		   ArrayList accessrules = new ArrayList();
		   accessrules.add(new AccessRule("/public_web_user",AccessRule.RULE_ACCEPT,false));
		 
		   accessrules.add(new AccessRule("/ca_functionality/basic_functions",AccessRule.RULE_ACCEPT,false));
		   accessrules.add(new AccessRule("/ca_functionality/view_certificate",AccessRule.RULE_ACCEPT,false));
		   accessrules.add(new AccessRule("/ca_functionality/create_certificate",AccessRule.RULE_ACCEPT,false));
		   accessrules.add(new AccessRule("/ca_functionality/store_certificate",AccessRule.RULE_ACCEPT,false));
		   accessrules.add(new AccessRule("/ra_functionality/view_end_entity",AccessRule.RULE_ACCEPT,false));			 
		   accessrules.add(new AccessRule("/ca",AccessRule.RULE_ACCEPT,true)); 
		   accessrules.add(new AccessRule("/endentityprofilesrules",AccessRule.RULE_ACCEPT,true)); 
		                                                       
		   agdl.addAccessRules(accessrules);
           
		  signalForAuthorizationTreeUpdate();
	      }catch(CreateException ce){}	       
	   }  
    }


     /**
     * Method to check if a user is authorized to a certain resource.
     *
     * @param admin the administrator about to be authorized, see se.anatom.ejbca.log.Admin class.
     * @param resource the resource to check authorization for.
     */
    public boolean isAuthorized(Admin admin, String resource) throws  AuthorizationDeniedException{
        if(updateNeccessary())
          updateAuthorizationTree(admin);
        return authorizer.isAuthorized(admin, resource);
    }

     /**
     * Method to check if a user is authorized to a certain resource without performing any logging.
     *
     * @param admin the administrator about to be authorized, see se.anatom.ejbca.log.Admin class.
     * @param resource the resource to check authorization for. 
     */
    public boolean isAuthorizedNoLog(Admin admin, String resource) throws AuthorizationDeniedException{
       if(updateNeccessary())
         updateAuthorizationTree(admin);
       return authorizer.isAuthorizedNoLog(admin, resource);
    }

    /**
     * Method to validate and check revokation status of a users certificate.
     *
     * @param certificate the users X509Certificate.
     *
     */

    public void authenticate(X509Certificate certificate) throws AuthenticationFailedException{
     authorizer.authenticate(certificate);
    }

   /**
    * Method to add an admingroup.
    *
    * @param admingroupname name of new admingroup, have to be unique.
    * @throws AdminGroupExistsException if admingroup already exists.
    */
    public void addAdminGroup(Admin admin, String admingroupname, int caid) throws AdminGroupExistsException {
      if(!(admingroupname.equals(DEFAULTGROUPNAME) && caid == ILogSessionLocal.INTERNALCAID)){
        
        boolean success=true;
        try{
          admingrouphome.findByPrimaryKey(new AdminGroupPK(admingroupname, caid));
          success=false;
        }catch(FinderException e){
        }
        if(success){
          try{
            admingrouphome.create(admingroupname, caid);
            success=true;
          }catch(CreateException e){
             error("Can't add admingroup:"+e.getMessage());
             success=false;
          }
        }

  
        if(success){
          logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Administratorgroup " + admingroupname + " added."); 
        }else{
          logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error adding administratorgroup "  + admingroupname + ".");
          throw new AdminGroupExistsException();
        }
      }  
    } // addAdminGroup

    /**
     * Method to remove a admingroup.
     */
    public void removeAdminGroup(Admin admin, String admingroupname, int caid){
      if(!(admingroupname.equals(DEFAULTGROUPNAME) && caid == ILogSessionLocal.INTERNALCAID)){        
        try{
           AdminGroupDataLocal agl = admingrouphome.findByPrimaryKey(new AdminGroupPK(admingroupname, caid));
          // Remove groups user entities.
           agl.removeAdminEntities(agl.getAdminEntityObjects());

          // Remove groups accessrules.
           Iterator iter = agl.getAccessRuleObjects().iterator();
           ArrayList remove = new ArrayList();
           while(iter.hasNext()){
             remove.add(((AccessRule) iter.next()).getAccessRule());  
           }
           agl.removeAccessRules(remove);
         
           agl.remove();
           signalForAuthorizationTreeUpdate();
         
           logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Administratorgroup " + admingroupname + " removed.");
        }catch(Exception e){
          error("RemoveAdminGroup: "+e);
          logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error removing administratorgroup " + admingroupname + ".");
        }
      }  
    } // removeAdminGroup

    /**
     * Metod to rename a admingroup
     *
     * @throws AdminGroupExistsException if admingroup already exists.
     */
    public void renameAdminGroup(Admin admin, String oldname, int caid, String newname) throws AdminGroupExistsException {
      if(!(oldname.equals(DEFAULTGROUPNAME) && caid == ILogSessionLocal.INTERNALCAID)){  
        boolean success = false;
        AdminGroupDataLocal agl = null;
        try{
          agl = admingrouphome.findByPrimaryKey(new AdminGroupPK(newname, caid));
          throw new AdminGroupExistsException();
        }catch(FinderException e){
          success = true;
        }
        if(success){
          try{
            agl =  admingrouphome.findByPrimaryKey(new AdminGroupPK(oldname, caid));
            Collection accessrules = agl.getAccessRuleObjects();
            Collection adminentities = agl.getAdminEntityObjects();
            AdminGroupDataLocal newagl = admingrouphome.create(newname, caid);
            newagl.addAccessRules(accessrules);
            newagl.addAdminEntities(adminentities);
            removeAdminGroup(admin, oldname, caid);
            signalForAuthorizationTreeUpdate();          
          }catch(Exception e){
            error("Can't rename admingroup:"+e.getMessage());
            success = false;
          }
        }

        if(success)
          logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Renamed administratorgroup " + oldname + " to " + newname + ".");
        else
          logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error renaming administratorgroup " + oldname + " to " + newname + ".");
      }
    } // renameAdminGroup

    

    /**
     * Method to get a reference to a admingroup.
     */

    public AdminGroup getAdminGroup(Admin admin, String admingroupname, int caid){
      AdminGroup returnval = null;
      try{
        returnval = (admingrouphome.findByPrimaryKey(new AdminGroupPK(admingroupname, caid))).getAdminGroup();
      }catch(Exception e){
          error("Can't get admingroup:"+e.getMessage());
      }
      return returnval;
    } // getAdminGroup


    /**
     * Returns the total number of admingroups
     */
    private Collection getAdminGroups(Admin admin){
      ArrayList returnval= new ArrayList();
      try{
        Iterator iter =  admingrouphome.findAll().iterator();
        while(iter.hasNext())
          returnval.add(((AdminGroupDataLocal) iter.next()).getAdminGroup());  
      }catch(FinderException e){}

      return returnval;
    } // getAdminGroups    
    
         
    /**
     * Returns a Collection of AdminGroup the administrator is authorized to.
     * The AdminGroup objects only contains only name and caid and no accessdata
     */
    
     public Collection getAuthorizedAdminGroupNames(Admin admin){
       ArrayList returnval = new ArrayList();
       HashSet authorizedcaids = new HashSet(authorizer.getAuthorizedCAIds(admin));
       try{
         Collection result = admingrouphome.findAll();
         Iterator i = result.iterator();

         while(i.hasNext()){
            AdminGroupDataLocal agdl = (AdminGroupDataLocal) i.next();
            if(authorizedcaids.contains(new Integer(agdl.getCAId()))){ 
              // check access rules  
              Iterator iter = agdl.getAccessRuleObjects().iterator();  
              boolean allauthorized = true;
              while(iter.hasNext()){
                String rule = ((AccessRule) iter.next()).getAccessRule();
                if(rule.startsWith(AvailableAccessRules.CAPREFIX)){  
                  if(!authorizedcaids.contains(new Integer(rule.substring(AvailableAccessRules.CAPREFIX.length())))){
                     allauthorized=false;   
                  }
                }    
              }
              if(allauthorized)
                if(!(agdl.getAdminGroupName().equals(DEFAULTGROUPNAME) && agdl.getCAId() == ILogSessionLocal.INTERNALCAID))  
                  returnval.add(agdl.getAdminGroupNames());  
            }
         }
       }catch(FinderException e){}
       return returnval;
     } // getAuthorizedAdminGroupNames
     
     /**
     * Adds a Collection of AccessRule to an an admin group.
     *
     */
    public void addAccessRules(Admin admin, String admingroupname, int caid, Collection accessrules){
      if(!(admingroupname.equals(DEFAULTGROUPNAME) && caid == ILogSessionLocal.INTERNALCAID)){
        try{
          (admingrouphome.findByPrimaryKey(new AdminGroupPK(admingroupname, caid))).addAccessRules(accessrules);
          signalForAuthorizationTreeUpdate();
          logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Added accessrules to admingroup : " + admingroupname );
        }catch(Exception e){
           error("Can't add access rule:"+e.getMessage());
           logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error adding accessrules to admingroup : " + admingroupname);
        }
      }  
    } // addAccessRules


     /**
     * Removes a Collection of (Sting) containing accessrules to remove from admin group.
     *
     */
    public void removeAccessRules(Admin admin, String admingroupname, int caid, Collection accessrules){
      if(!(admingroupname.equals(DEFAULTGROUPNAME) && caid == ILogSessionLocal.INTERNALCAID)){
       try{
         (admingrouphome.findByPrimaryKey(new AdminGroupPK(admingroupname, caid))).removeAccessRules(accessrules);
         signalForAuthorizationTreeUpdate();
         logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Removed accessrules from admingroup : " + admingroupname );
        }catch(Exception e){
          logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Error removing accessrules from admingroup : " + admingroupname );
        }
      } 
    } // removeAccessRules



     /**
     * Adds a Collection of AdminEnity to the admingroup. Changes their values if they already exists.
     *
     */

    public void addAdminEntities(Admin admin, String admingroupname, int caid, Collection adminentities){ 
      if(!(admingroupname.equals(DEFAULTGROUPNAME) && caid == ILogSessionLocal.INTERNALCAID)){
        try{
          (admingrouphome.findByPrimaryKey(new AdminGroupPK(admingroupname, caid))).addAdminEntities(adminentities);
          signalForAuthorizationTreeUpdate();
          logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Added administrator entities to administratorgroup " + admingroupname);
        }catch(Exception e){
          error("Can't add admin entities: ",e);
          logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error adding administrator entities to administratorgroup " + admingroupname);
        }
      }  
    } // addAdminEntity


     /**
     * Removes a Collection of AdminEntity from the administrator group.
     *
     */
    public void removeAdminEntities(Admin admin, String admingroupname, int caid, Collection adminentities){
      if(!(admingroupname.equals(DEFAULTGROUPNAME) && caid == ILogSessionLocal.INTERNALCAID)){
        try{
          (admingrouphome.findByPrimaryKey(new AdminGroupPK(admingroupname, caid))).removeAdminEntities(adminentities);
          signalForAuthorizationTreeUpdate();
          logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES,"Removed administrator entities from administratorgroup " + admingroupname);
        }catch(Exception e){
          error("Can't add admin entities: ",e);
          logsession.log(admin, caid, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES,"Error removing administrator entities from administratorgroup " + admingroupname);
        }
      }  
    } // removeAdminEntity



    /**
     * Method used to collect an administrators available access rules based on which rule
     * he himself is authorized to.
     *
     * @param admin is the administrator calling the method.
     * @return a Collection of String containing available accessrules.
     */
    
   public Collection getAuthorizedAvailableAccessRules(Admin admin){
       AvailableAccessRules aar = null;
       try{
         aar = new AvailableAccessRules(admin, authorizer, getRaAdminSession(), customaccessrules);
       }catch(Exception e){
          throw new EJBException(e);   
       }
         
       return aar.getAvailableAccessRules(admin);
   }

    /**
     * Method used to return an Collection of Integers indicating which CAids a administrator
     * is authorized to access.
     */       
    public Collection getAuthorizedCAIds(Admin admin){
       return authorizer.getAuthorizedCAIds(admin);   
    }

    
    /**
     * Method used to return an Collection of Integers indicating which end entity profiles
     * the administrator is authorized to view.
     *
     * @param admin, the administrator 
     * @rapriviledge should be one of the end entity profile authorization constans defined in AvailableAccessRules.
     */       
    public Collection getAuthorizedEndEntityProfileIds(Admin admin, String rapriviledge){
       return authorizer.getAuthorizedEndEntityProfileIds(admin, rapriviledge);   
    }    
    /**
     * Method to check if an end entity profile exists in any end entity profile rules. Used to avoid desyncronization of profilerules.
     *
     * @param profileid the profile id to search for.
     * @return true if profile exists in any of the accessrules.
     */

    public boolean existsEndEntityProfileInRules(Admin admin, int profileid){   
        debug(">existsEndEntityProfileInRules()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int count = 1; // return true as default.

        String whereclause = "accessRule  LIKE '" + AvailableAccessRules.ENDENTITYPROFILEPREFIX + profileid + "%'";

        try{
           // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select COUNT(*) from AccessRulesData where " + whereclause);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            if(rs.next()){
              count = rs.getInt(1);
            }
            debug("<existsEndEntityProfileInRules()");
            return count > 0;

        }catch(Exception e){
          throw new EJBException(e);
        }finally{
           try{
             if(rs != null) rs.close();
             if(ps != null) ps.close();
             if(con!= null) con.close();
           }catch(SQLException se){
               error("Error when cleaning up: ", se);
           }
        }       
    }

    /**
     * Method to check if a ca exists in any ca specific rules. Used to avoid desyncronization of CA rules when ca is removed
     * @param caid the ca id to search for.
     * @return true if ca exists in any of the accessrules.
     */

    public boolean existsCAInRules(Admin admin, int caid){
      return existsCAInAdminGroups(caid) && existsCAInAccessRules(caid);         
    } // existsCAInRules   
    
    /**
     * Help function to existsCAInRules, checks if caid axists among admingroups.
     */
    private boolean existsCAInAdminGroups(int caid){
        debug(">existsCAInAdminGroups()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int count = 1; // return true as default.

        String whereclause = "cAId = '" + caid +"'";

        try{
           // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select COUNT(*) from AdminGroupData where " + whereclause);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            if(rs.next()){
              count = rs.getInt(1);
            }
            debug("<existsCAInAdminGroupss()");
            return count > 0;

        }catch(Exception e){
          throw new EJBException(e);
        }finally{
           try{
             if(rs != null) rs.close();
             if(ps != null) ps.close();
             if(con!= null) con.close();
           }catch(SQLException se){
               error("Error when cleaning up: ", se);
           }
        }               
    }
    
    /**
     * Help function to existsCAInRules, checks if caid axists among accessrules.
     */ 
    private boolean existsCAInAccessRules(int caid){
        debug(">existsCAInAccessRules()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int count = 1; // return true as default.

        String whereclause = "accessRule  LIKE '" + AvailableAccessRules.CAPREFIX + caid + "%'";

        try{
           // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select COUNT(*) from AccessRulesData where " + whereclause);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            if(rs.next()){
              count = rs.getInt(1);
            }
            debug("<existsCAInAccessRules()");
            return count > 0;

        }catch(Exception e){
          throw new EJBException(e);
        }finally{
           try{
             if(rs != null) rs.close();
             if(ps != null) ps.close();
             if(con!= null) con.close();
           }catch(SQLException se){
               error("Error when cleaning up: ", se);
           }
        }    
    }
    
    /**
     * Returns a reference to the AuthorizationTreeUpdateDataBean
     */ 
    private AuthorizationTreeUpdateDataLocal getAuthorizationTreeUpdateData(){
     AuthorizationTreeUpdateDataLocal atu = null; 
       try{
          atu = authorizationtreeupdatehome.findByPrimaryKey(new Integer(AuthorizationTreeUpdateDataLocalHome.AUTHORIZATIONTREEUPDATEDATA));
       }catch(FinderException e){
          try{
            atu = authorizationtreeupdatehome.create();  
          }catch(CreateException ce){
             error("Error creating AuthorizationTreeUpdateDataBean :", ce);
             throw new EJBException(ce);
          }   
       }
       return atu;    
    }
     
        
    /** 
     * Method used check if a reconstruction of authorization tree is needed in the
     * authorization beans. 
     *
     * @returns true if update is needed.
     */
    
    private boolean updateNeccessary(){
      System.out.println("Update neccessary :" + (getAuthorizationTreeUpdateData().updateNeccessary(this.authorizationtreeupdate) && lastupdatetime < ((new java.util.Date()).getTime() - IAuthorizationSessionRemote.MINTIMEBETWEENUPDATES)));           
       return getAuthorizationTreeUpdateData().updateNeccessary(this.authorizationtreeupdate) && lastupdatetime < ((new java.util.Date()).getTime() - IAuthorizationSessionRemote.MINTIMEBETWEENUPDATES);      
    } // updateNeccessary
    
    /**
     * method updating authorization tree.
     */
    private void updateAuthorizationTree(Admin admin){
      System.out.println("Time to update authorization tree.");  
      authorizer.buildAccessTree(getAdminGroups(admin));  
      this.authorizationtreeupdate= getAuthorizationTreeUpdateData().getAuthorizationTreeUpdateNumber();
      this.lastupdatetime = (new java.util.Date()).getTime();  
    }

    /** 
     * Method incrementing the authorizationtreeupdatenumber and thereby signaling 
     * to other beans that they should reconstruct their accesstrees. 
     *
     */    
    private void signalForAuthorizationTreeUpdate(){
              System.out.println("Signal for update."); 
       getAuthorizationTreeUpdateData().incrementAuthorizationTreeUpdateNumber();
    }
    
} // LocalAvailableAccessRulesDataBean

