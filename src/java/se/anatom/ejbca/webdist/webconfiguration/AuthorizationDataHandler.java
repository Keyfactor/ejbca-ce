package se.anatom.ejbca.webdist.webconfiguration;

import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Iterator;
import java.util.Vector;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.ra.authorization.*;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.log.ILogSessionRemote;

/**
 * A class handling the profile data. It saves and retrieves them currently from a database.
 *
 * @author  Philip Vendil
 * @version $Id: AuthorizationDataHandler.java,v 1.9 2002-10-24 20:13:55 herrvendil Exp $
 */
public class AuthorizationDataHandler {

    public static final int ACCESS_RULE_RESOURCE = 0;
    public static final int ACCESS_RULE_RULE      = 1;
    public static final int ACCESS_RULE_RECURSIVE = 2;

    public static final int ADMIN_ENTITY_MATCHWITH  = 0;
    public static final int ADMIN_ENTITY_MATCHTYPE  = 1;
    public static final int ADMIN_ENTITY_MATCHVALUE = 2;

    /** Creates a new instance of ProfileDataHandler */
    public AuthorizationDataHandler(GlobalConfiguration globalconfiguration,ILogSessionRemote logsession, Admin administrator) throws RemoteException, NamingException, CreateException{
       InitialContext jndicontext = new InitialContext();
       IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("AuthorizationSession"),
                                                                                 IAuthorizationSessionHome.class);
       authorizationsession = authorizationsessionhome.create(globalconfiguration, administrator);
       
       Collection names = authorizationsession.getAvailableAccessRules();
       if(names.size()==0){
          Vector rules = new Vector();
          String[] defaultrules = globalconfiguration.getDefaultAvailableResources();
          for(int i = 0; i < defaultrules.length ; i++){
            rules.addElement( defaultrules[i]);
          }
         authorizationsession.addAvailableAccessRules(rules);
       }

       availableresources = new AvailableResources(globalconfiguration);
       authorize = new EjbcaAuthorization(getAdminGroups(), globalconfiguration, logsession, administrator, LogEntry.MODULE_ADMINWEB);
    }
    // Public methods.
    /**
     * Method to check if a admin is authorized to a resource
     *
     * @param admininformation information about the admin to be authorized.
     * @param resource the resource to look up.
     * @returns true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorized(AdminInformation admininformation, String resource) throws AuthorizationDeniedException{
      return authorize.isAuthorized(admininformation, resource);
    }
    
    /**
     * Method to check if a admin is authorized to a resource without performing any logging.
     *
     * @param admininformation information about the admin to be authorized.
     * @param resource the resource to look up.
     * @returns true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorizedNoLog(AdminInformation admininformation, String resource) throws AuthorizationDeniedException{
      return authorize.isAuthorizedNoLog(admininformation, resource);
    }    
    
    /**
     * Method that authenticates a certificate by verifying signature, checking validity and lookup if certificate is revoked.
     *
     * @param certificate the certificate to be authenticated. 
     *
     * @throws AuthenticationFailedException if authentication failed. 
     */
    public void authenticate(X509Certificate certificate) throws AuthenticationFailedException {
      authorize.authenticate(certificate);
    }
    
    // Methods used with admingroup data
        /** Method to add a new admingroup to the access control data.*/
    public void addAdminGroup(String name) throws AdmingroupExistsException, RemoteException{
        if(!authorizationsession.addAdminGroup(name))
          throw new AdmingroupExistsException();
    
        authorize.buildAccessTree(authorizationsession.getAdminGroups());        
    }

    /** Method to remove a admingroup.*/
    public void removeAdminGroup(String name) throws RemoteException{
        authorizationsession.removeAdminGroup(name);
        authorize.buildAccessTree(authorizationsession.getAdminGroups());        
    }

    /** Method to rename a admingroup. */
    public void renameAdminGroup(String oldname, String newname) throws AdmingroupExistsException, RemoteException{
        if(!authorizationsession.renameAdminGroup(oldname,newname))
          throw new AdmingroupExistsException();
        
         authorize.buildAccessTree(authorizationsession.getAdminGroups());
    }

    /** Method to retrieve all admingroup's names.*/
    public String[] getAdminGroupnames() throws RemoteException{
        return authorizationsession.getAdminGroupnames();
    }

    public AdminGroup[] getAdminGroups() throws RemoteException{
      return authorizationsession.getAdminGroups();
    }

    /** Method to add an array of access rules to a admingroup. The accessrules must be a 2d array where
     *  the outer array specifies the field using ACCESS_RULE constants. */
    public void addAccessRules(String groupname, String[][] accessrules) throws RemoteException{
        try{
          for(int i=0; i < accessrules.length; i++){
            authorizationsession.addAccessRule(groupname, accessrules[i][ACCESS_RULE_RESOURCE],
                                java.lang.Integer.valueOf(accessrules[i][ACCESS_RULE_RULE]).intValue(),
                                java.lang.Boolean.valueOf(accessrules[i][ACCESS_RULE_RECURSIVE]).booleanValue());
          }
          authorize.buildAccessTree(authorizationsession.getAdminGroups());          
        }catch (Exception e){
            // Do not add erronios rules.
        }
    }

    /** Method to remove an array of access rules from a admingroup.*/
    public void removeAccessRules(String groupname, String[][] accessrules) throws RemoteException{
        int arraysize = accessrules.length;
        try{
          for(int i=0; i < arraysize; i++){
            authorizationsession.removeAccessRule(groupname, accessrules[i][ACCESS_RULE_RESOURCE]);
          }
          
          authorize.buildAccessTree(authorizationsession.getAdminGroups());  
        }catch (Exception e){
            // Do not add erronios rules.
        }
    }

    /** Method that returns all access rules applied to a group.*/
    public String[][] getAccessRules(String groupname) throws RemoteException{
        AccessRule[] accessrules = null;
        String[][]   returnarray = null;

        accessrules=authorizationsession.getAccessRules(groupname);
        if(accessrules != null){
          returnarray = new String[accessrules.length][3];
          for(int i = 0; i < accessrules.length; i++){
             returnarray[i][ACCESS_RULE_RESOURCE] = accessrules[i].getResource();
             returnarray[i][ACCESS_RULE_RULE] = String.valueOf(accessrules[i].getRule());
             returnarray[i][ACCESS_RULE_RECURSIVE] = String.valueOf(accessrules[i].isRecursive());
          }
        }
        
        return returnarray;
    }

    /** Method that returns all avaliable rules to a admingroup. It checks the filesystem for
     * all resources beneaf document root that isn't set hidden or already applied to this group.*/
    public String[] getAvailableRules(String groupname) throws RemoteException{
      return authorizationsession.getAdminGroup(groupname).nonUsedResources(availableresources.getResources());
    }

      /** Method to add an array of admin entities  to a admingroup. A admin entity
       *  van be a single admin or an entire organization depending on how it's match
       *  rules i set. The adminentities must be a 2d array where
       *  the outer array specifies the fields using USER_ENTITY constants.*/
    public void addAdminEntities(String groupname, String[][] adminentities) throws RemoteException{
       int arraysize = adminentities.length;
        try{
          for(int i=0; i < arraysize; i++){
            authorizationsession.addAdminEntity(groupname,
                                Integer.parseInt(adminentities[i][ADMIN_ENTITY_MATCHWITH]),
                                Integer.parseInt(adminentities[i][ADMIN_ENTITY_MATCHTYPE]),
                                adminentities[i][ADMIN_ENTITY_MATCHVALUE]);
          }
          authorize.buildAccessTree(authorizationsession.getAdminGroups());          
       }catch (Exception e){
            // Do not add erronios rules.
       }
    }

        /** Method to remove an array of admin entities from a admingroup.*/
    public void removeAdminEntities(String groupname, String[][] adminentities) throws RemoteException{
      int arraysize = adminentities.length;
      try{
        for(int i=0; i < arraysize; i++){
           authorizationsession.removeAdminEntity(groupname, Integer.parseInt(adminentities[i][ADMIN_ENTITY_MATCHWITH])
                                                               ,Integer.parseInt(adminentities[i][ADMIN_ENTITY_MATCHTYPE])
                                                               ,adminentities[i][ADMIN_ENTITY_MATCHVALUE]);
        }
        authorize.buildAccessTree(authorizationsession.getAdminGroups());
      }catch (Exception e){
        // Do not remove erronios rules.
      }
    }

    /** Method that returns all admin entities belonging to a group.*/
    public String[][] getAdminEntities(String groupname) throws RemoteException{
      AdminEntity[] adminentities;
      String[][]   returnarray = null;

      adminentities=authorizationsession.getAdminEntities(groupname);
      if(adminentities != null){
        returnarray = new String[adminentities.length][3];
        for(int i = 0; i < adminentities.length; i++){
          returnarray[i][ADMIN_ENTITY_MATCHWITH] = String.valueOf(adminentities[i].getMatchWith());
          returnarray[i][ADMIN_ENTITY_MATCHTYPE] = String.valueOf(adminentities[i].getMatchType());
          returnarray[i][ADMIN_ENTITY_MATCHVALUE] = adminentities[i].getMatchValue();
        }
      }
      return returnarray;
    }

    // Metods used with available access rules data

    /**
     * Method to add an access rule.
     */

    public void addAvailableAccessRule(String name) throws RemoteException{
      authorizationsession.addAvailableAccessRule(name);
    } // addAvailableAccessRule

    /**
     * Method to add an Collection of access rules.
     */

    public void addAvailableAccessRules(Collection names) throws RemoteException{
      authorizationsession.addAvailableAccessRules(names);
    } //  addAvailableAccessRules

    /**
     * Method to remove an access rule.
     */

    public void removeAvailableAccessRule(String name)  throws RemoteException{
      authorizationsession.removeAvailableAccessRule(name);
    } // removeAvailableAccessRule

    /**
     * Method to remove an Collection of access rules.
     */

    public void removeAvailableAccessRules(Collection names)  throws RemoteException{
      authorizationsession.removeAvailableAccessRules(names);
    } // removeAvailableAccessRules

    /**
     * Method that returns a Collection of Strings containing all access rules.
     */

    public Collection getAvailableAccessRules() throws RemoteException{
       return authorizationsession.getAvailableAccessRules();
    } // getAvailableAccessRules

    /**
     * Checks wheither an access rule exists in the database.
     */

    public boolean existsAvailableAccessRule(String name) throws RemoteException{
      return authorizationsession.existsAvailableAccessRule(name);
    } // existsAvailableAccessRule


    // Private fields
    private IAuthorizationSessionRemote authorizationsession;
    private AvailableResources        availableresources;
    private EjbcaAuthorization          authorize;
}
