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
 * @version $Id: AuthorizationDataHandler.java,v 1.8 2002-09-17 09:19:47 herrvendil Exp $
 */
public class AuthorizationDataHandler {

    public static final int ACCESS_RULE_DIRECTORY = 0;
    public static final int ACCESS_RULE_RULE      = 1;
    public static final int ACCESS_RULE_RECURSIVE = 2;

    public static final int USER_ENTITY_MATCHWITH  = 0;
    public static final int USER_ENTITY_MATCHTYPE  = 1;
    public static final int USER_ENTITY_MATCHVALUE = 2;

    /** Creates a new instance of ProfileDataHandler */
    public AuthorizationDataHandler(GlobalConfiguration globalconfiguration,ILogSessionRemote logsession, Admin administrator) throws RemoteException, NamingException, CreateException{
       InitialContext jndicontext = new InitialContext();
       IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("AuthorizationSession"),
                                                                                 IAuthorizationSessionHome.class);
       authorizationsession = authorizationsessionhome.create(globalconfiguration, administrator);
       
       Collection names = authorizationsession.getAvailableAccessRules();
       if(names.size()==0){
          Vector rules = new Vector();
          String[] defaultrules = globalconfiguration.getDefaultAvailableDirectories();
          for(int i = 0; i < defaultrules.length ; i++){
            rules.addElement( defaultrules[i]);
          }
         authorizationsession.addAvailableAccessRules(rules);
       }

       availabledirectories = new AvailableDirectories(globalconfiguration);
       authorize = new EjbcaAuthorization(getUserGroups(), globalconfiguration, logsession, administrator, LogEntry.MODULE_ADMINWEB);
    }
    // Public methods.
    /**
     * Method to check if a user is authorized to a resource
     *
     * @param userinformation information about the user to be authorized.
     * @param resource the resource to look up.
     * @returns true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorized(UserInformation userinformation, String resource) throws AuthorizationDeniedException{
      return authorize.isAuthorized(userinformation, resource);
    }
    
    /**
     * Method to check if a user is authorized to a resource without performing any logging.
     *
     * @param userinformation information about the user to be authorized.
     * @param resource the resource to look up.
     * @returns true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorizedNoLog(UserInformation userinformation, String resource) throws AuthorizationDeniedException{
      return authorize.isAuthorizedNoLog(userinformation, resource);
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
    
    // Methods used with usergroup data
        /** Method to add a new usergroup to the access control data.*/
    public void addUserGroup(String name) throws UsergroupExistsException, RemoteException{
        if(!authorizationsession.addUserGroup(name))
          throw new UsergroupExistsException();
    
        authorize.buildAccessTree(authorizationsession.getUserGroups());        
    }

    /** Method to remove a usergroup.*/
    public void removeUserGroup(String name) throws RemoteException{
        authorizationsession.removeUserGroup(name);
        authorize.buildAccessTree(authorizationsession.getUserGroups());        
    }

    /** Method to rename a usergroup. */
    public void renameUserGroup(String oldname, String newname) throws UsergroupExistsException, RemoteException{
        if(!authorizationsession.renameUserGroup(oldname,newname))
          throw new UsergroupExistsException();
        
         authorize.buildAccessTree(authorizationsession.getUserGroups());
    }

    /** Method to retrieve all usergroup's names.*/
    public String[] getUserGroupnames() throws RemoteException{
        return authorizationsession.getUserGroupnames();
    }

    public UserGroup[] getUserGroups() throws RemoteException{
      return authorizationsession.getUserGroups();
    }

    /** Method to add an array of access rules to a usergroup. The accessrules must be a 2d array where
     *  the outer array specifies the field using ACCESS_RULE constants. */
    public void addAccessRules(String groupname, String[][] accessrules) throws RemoteException{
        try{
          for(int i=0; i < accessrules.length; i++){
            authorizationsession.addAccessRule(groupname, accessrules[i][ACCESS_RULE_DIRECTORY],
                                java.lang.Integer.valueOf(accessrules[i][ACCESS_RULE_RULE]).intValue(),
                                java.lang.Boolean.valueOf(accessrules[i][ACCESS_RULE_RECURSIVE]).booleanValue());
          }
          authorize.buildAccessTree(authorizationsession.getUserGroups());          
        }catch (Exception e){
            // Do not add erronios rules.
        }
    }

    /** Method to remove an array of access rules from a usergroup.*/
    public void removeAccessRules(String groupname, String[][] accessrules) throws RemoteException{
        int arraysize = accessrules.length;
        try{
          for(int i=0; i < arraysize; i++){
            authorizationsession.removeAccessRule(groupname, accessrules[i][ACCESS_RULE_DIRECTORY]);
          }
          
          authorize.buildAccessTree(authorizationsession.getUserGroups());  
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
             returnarray[i][ACCESS_RULE_DIRECTORY] = accessrules[i].getDirectory();
             returnarray[i][ACCESS_RULE_RULE] = String.valueOf(accessrules[i].getRule());
             returnarray[i][ACCESS_RULE_RECURSIVE] = String.valueOf(accessrules[i].isRecursive());
          }
        }
        
        return returnarray;
    }

    /** Method that returns all avaliable rules to a usergroup. It checks the filesystem for
     * all directories beneaf document root that isn't set hidden or already applied to this group.*/
    public String[] getAvailableRules(String groupname) throws RemoteException{
      return authorizationsession.getUserGroup(groupname).nonUsedDirectories(availabledirectories.getDirectories());
    }

      /** Method to add an array of user entities  to a usergroup. A user entity
       *  van be a single user or an entire organization depending on how it's match
       *  rules i set. The userentities must be a 2d array where
       *  the outer array specifies the fields using USER_ENTITY constants.*/
    public void addUserEntities(String groupname, String[][] userentities) throws RemoteException{
       int arraysize = userentities.length;
        try{
          for(int i=0; i < arraysize; i++){
            authorizationsession.addUserEntity(groupname,
                                Integer.parseInt(userentities[i][USER_ENTITY_MATCHWITH]),
                                Integer.parseInt(userentities[i][USER_ENTITY_MATCHTYPE]),
                                userentities[i][USER_ENTITY_MATCHVALUE]);
          }
          authorize.buildAccessTree(authorizationsession.getUserGroups());          
       }catch (Exception e){
            // Do not add erronios rules.
       }
    }

        /** Method to remove an array of user entities from a usergroup.*/
    public void removeUserEntities(String groupname, String[][] userentities) throws RemoteException{
      int arraysize = userentities.length;
      try{
        for(int i=0; i < arraysize; i++){
           authorizationsession.removeUserEntity(groupname, Integer.parseInt(userentities[i][USER_ENTITY_MATCHWITH])
                                                               ,Integer.parseInt(userentities[i][USER_ENTITY_MATCHTYPE])
                                                               ,userentities[i][USER_ENTITY_MATCHVALUE]);
        }
        authorize.buildAccessTree(authorizationsession.getUserGroups());
      }catch (Exception e){
        // Do not remove erronios rules.
      }
    }

    /** Method that returns all user entities belonging to a group.*/
    public String[][] getUserEntities(String groupname) throws RemoteException{
      UserEntity[] userentities;
      String[][]   returnarray = null;

      userentities=authorizationsession.getUserEntities(groupname);
      if(userentities != null){
        returnarray = new String[userentities.length][3];
        for(int i = 0; i < userentities.length; i++){
          returnarray[i][USER_ENTITY_MATCHWITH] = String.valueOf(userentities[i].getMatchWith());
          returnarray[i][USER_ENTITY_MATCHTYPE] = String.valueOf(userentities[i].getMatchType());
          returnarray[i][USER_ENTITY_MATCHVALUE] = userentities[i].getMatchValue();
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
    private AvailableDirectories        availabledirectories;
    private EjbcaAuthorization          authorize;
}
