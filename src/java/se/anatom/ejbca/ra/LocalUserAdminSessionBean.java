package se.anatom.ejbca.ra;

import java.io.*;
import java.util.*;

import java.sql.*;
import javax.sql.DataSource;
import javax.naming.*;
import java.rmi.*;
import javax.rmi.*;
import javax.ejb.*;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.authorization.EndEntityProfileAuthorizationProxy;
import se.anatom.ejbca.util.query.*;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.authorization.IAuthorizationSessionLocalHome;
import se.anatom.ejbca.ra.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocalHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.log.LogEntry;

/**
 * Administrates users in the database using UserData Entity Bean.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalUserAdminSessionBean.java,v 1.29 2002-10-24 20:10:07 herrvendil Exp $
 */
public class LocalUserAdminSessionBean extends BaseSessionBean  {

    /** The home interface of  GlobalConfiguration entity bean */
    private GlobalConfigurationDataLocalHome globalconfigurationhome = null;

    /** Var containing the global configuration. */
    private GlobalConfiguration globalconfiguration;

    /** The local interface of RaAdmin Session Bean. */
    private IRaAdminSessionLocal raadminsession;

    /** The remote interface of the certificate store session bean */
    private ICertificateStoreSessionRemote certificatesession;

    /** The remote interface of the log session bean */
    private ILogSessionRemote logsession;
    
    private UserDataLocalHome home = null;
    /** Columns in the database used in select */
    private final String USERDATA_COL = "username, subjectDN, subjectAltName, subjectEmail, status, type, clearpassword, timeCreated, timeModified, endEntityprofileId, certificateProfileId, tokenType, hardTokenIssuerId";
    /** Var holding JNDI name of datasource */
    private String dataSource = "java:/DefaultDS";

    /** Var optimizing authorization lookups. */
    private EndEntityProfileAuthorizationProxy profileauthproxy;
    
    /** Var containing iformation about administrator using the bean.*/
    private Admin admin = null;
    
    /**
     * Default create for SessionBean.
     * @param administrator information about the administrator using this sessionbean.
     * @throws CreateException if bean instance can't be created
     * @see se.anatom.ejbca.log.Admin
     */
    public void ejbCreate (Admin administrator) throws CreateException {
      debug(">ejbCreate()");
      try{  
        home = (UserDataLocalHome) lookup("java:comp/env/ejb/UserDataLocal", UserDataLocalHome.class);
        globalconfigurationhome = (GlobalConfigurationDataLocalHome)lookup("java:comp/env/ejb/GlobalConfigurationDataLocal", GlobalConfigurationDataLocalHome.class);
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
       
        this.globalconfiguration = loadGlobalConfiguration();
        
        this.admin= administrator;
        ILogSessionHome logsessionhome = (ILogSessionHome) lookup("java:comp/env/ejb/LogSession",ILogSessionHome.class);       
        logsession = logsessionhome.create(); 
         
        IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) lookup("java:comp/env/ejb/AuthorizationSessionLocal",IAuthorizationSessionLocalHome.class);
        IAuthorizationSessionLocal authorizationsession = authorizationsessionhome.create(globalconfiguration, administrator);
        IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) lookup("java:comp/env/ejb/RaAdminSessionLocal", IRaAdminSessionLocalHome.class);
        raadminsession = raadminsessionhome.create(administrator);

        ICertificateStoreSessionHome certificatesessionhome = (ICertificateStoreSessionHome) lookup("java:comp/env/ejb/CertificateStoreSession", ICertificateStoreSessionHome.class);
        certificatesession = certificatesessionhome.create(administrator);        
        profileauthproxy = new EndEntityProfileAuthorizationProxy(administrator.getAdminInformation(), authorizationsession);        
        debug("DataSource=" + dataSource);

      }catch(Exception e){
        throw new EJBException(e.getMessage());
      }

    }

    /** Gets connection to Datasource used for manual SQL searches
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
        return ds.getConnection();
    } //getConnection

   /**
    * Implements IUserAdminSession::addUser.
    * Implements a mechanism that uses UserDataEntity Bean.
    */
    public void addUser(String username, String password, String dn, String subjectaltname, String email, boolean clearpwd, int endentityprofileid, int certificateprofileid, 
                         boolean administrator, boolean keyrecoverable, int tokentype, int hardwaretokenissuerid)
                         throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, RemoteException {
        debug(">addUser("+username+", password, "+dn+", "+email+")");
        if(globalconfiguration.getEnableEndEntityProfileLimitations()){
          // Check if user fulfills it's profile.
          EndEntityProfile profile = raadminsession.getEndEntityProfile(endentityprofileid);
          try{
            profile.doesUserFullfillEndEntityProfile(username, password, dn, subjectaltname, email, certificateprofileid, clearpwd, 
                                                    administrator, keyrecoverable, tokentype, hardwaretokenissuerid);
          }catch( UserDoesntFullfillEndEntityProfile udfp){ 
            logsession.log(admin, LogEntry.MODULE_RA,  new java.util.Date(),username, null, LogEntry.EVENT_ERROR_ADDEDENDENTITY,"Userdata didn'nt fullfill end entity profile. " + udfp.getMessage() ); 
            throw new UserDoesntFullfillEndEntityProfile(udfp.getMessage());   
          }  

            // Check if administrator is authorized to add user.
            if(!profileauthproxy.getEndEntityProfileAuthorization(endentityprofileid,EndEntityProfileAuthorizationProxy.CREATE_RIGHTS)){
              logsession.log(admin, LogEntry.MODULE_RA,  new java.util.Date(),username, null, LogEntry.EVENT_ERROR_ADDEDENDENTITY,"Administrator not authorized");   
              throw new AuthorizationDeniedException("Administrator not authorized to create user.");  
            }  
        }           
        try{
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1=null;
            data1 = home.create(username, password, dn);
            if(subjectaltname != null )
                data1.setSubjectAltName(subjectaltname); 
            
            if(email != null)
                data1.setSubjectEmail(email);
            
            data1.setType(makeType(administrator, keyrecoverable));
            data1.setEndEntityProfileId(endentityprofileid);
            data1.setCertificateProfileId(certificateprofileid);
            data1.setTokenType(tokentype);
            data1.setHardTokenIssuerId(hardwaretokenissuerid);
            
            if(clearpwd){
              try {
                if (password == null){
                  data1.setClearPassword("");
                }
                else{
                  data1.setOpenPassword(password);
                }
              } catch (java.security.NoSuchAlgorithmException nsae)
              {
                debug("NoSuchAlgorithmException while setting password for user "+username);
                throw new EJBException(nsae);
              }
            }
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_ADDEDENDENTITY,""); 

        }catch (Exception e) {
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_ADDEDENDENTITY,""); 
            throw new EJBException(e.getMessage());
        }

        debug("<addUser("+username+", password, "+dn+", "+email+")");
    } // addUser

   /**
    * Implements IUserAdminSession::changeUser.
    * Implements a mechanism that uses UserDataEntity Bean.
    */
    public void changeUser(String username,  String dn, String subjectaltname, String email, int endentityprofileid, int certificateprofileid,
                           boolean administrator, boolean keyrecoverable, int tokentype, int hardwaretokenissuerid)
                              throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, RemoteException {
        debug(">changeUser("+username+", "+dn+", "+email+")");
        // Check if user fulfills it's profile.
        if(globalconfiguration.getEnableEndEntityProfileLimitations()){
        EndEntityProfile profile = raadminsession.getEndEntityProfile(endentityprofileid);
        try{
          profile.doesUserFullfillEndEntityProfileWithoutPassword(username,  dn, subjectaltname, email, certificateprofileid,
                                                                 administrator, keyrecoverable, tokentype, hardwaretokenissuerid);
        }catch(UserDoesntFullfillEndEntityProfile udfp){  
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_CHANGEDENDENTITY,"Userdata didn'nt fullfill end entity profile. + " + udfp.getMessage());                
          throw new UserDoesntFullfillEndEntityProfile(udfp.getMessage());   
        }  
        // Check if administrator is authorized to edit user. 
          if(!profileauthproxy.getEndEntityProfileAuthorization(endentityprofileid,EndEntityProfileAuthorizationProxy.EDIT_RIGHTS)){
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_CHANGEDENDENTITY,"Administrator not authorized");               
            throw new AuthorizationDeniedException("Administrator not authorized to edit user.");  
          }  
        }        

        try {
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1= home.findByPrimaryKey(pk);

            data1.setSubjectDN(CertTools.stringToBCDNString(dn));
            if(subjectaltname != null )
                data1.setSubjectAltName(subjectaltname); 
            
            if(email != null)
                data1.setSubjectEmail(email);
            
            data1.setType(makeType(administrator, keyrecoverable));
            data1.setEndEntityProfileId(endentityprofileid);
            data1.setCertificateProfileId(certificateprofileid);
            data1.setTokenType(tokentype);
            data1.setHardTokenIssuerId(hardwaretokenissuerid);
            
            data1.setTimeModified((new java.util.Date()).getTime());
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_CHANGEDENDENTITY,"");
        }
        catch (Exception e) {
            logsession.log(admin, LogEntry.MODULE_RA,  new java.util.Date(),username, null, LogEntry.EVENT_ERROR_CHANGEDENDENTITY,""); 
            throw new EJBException(e.getMessage());
        }
        debug("<changeUser("+username+", password, "+dn+", "+email+")");
    } // changeUser


   /**
    * Implements IUserAdminSession::deleteUser.
    * Implements a mechanism that uses UserData Entity Bean.
    */
    public void deleteUser(String username) throws AuthorizationDeniedException, RemoteException{
        debug(">deleteUser("+username+")");
        // Check if administrator is authorized to delete user.
        if(globalconfiguration.getEnableEndEntityProfileLimitations()){
          try{
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1 = home.findByPrimaryKey(pk);     
            if(!profileauthproxy.getEndEntityProfileAuthorization(data1.getEndEntityProfileId(),EndEntityProfileAuthorizationProxy.DELETE_RIGHTS)){
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_DELETEENDENTITY,"Administrator not authorized");                     
                throw new AuthorizationDeniedException("Administrator not authorized to delete user."); 
            }    
          }
          catch(FinderException e){
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_DELETEENDENTITY,"Couldn't find username in database");               
            throw new EJBException(e.getMessage());            
          }    
        }  
        try {
            UserDataPK pk = new UserDataPK(username);
            home.remove(pk);
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_DELETEDENDENTITY,"");
        }
        catch (Exception e) {
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_DELETEENDENTITY,"");
            throw new EJBException(e.getMessage());
        }
        debug("<deleteUser("+username+")");
    } // deleteUser

   /**
    * Implements IUserAdminSession::setUserStatus.
    * Implements a mechanism that uses UserData Entity Bean.
    */
    public void setUserStatus(String username, int status) throws AuthorizationDeniedException, FinderException, RemoteException {
        debug(">setUserStatus("+username+", "+status+")");
        // Check if administrator is authorized to edit user.
        if(globalconfiguration.getEnableEndEntityProfileLimitations()){         
          try{
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1 = home.findByPrimaryKey(pk);              
            if(!profileauthproxy.getEndEntityProfileAuthorization(data1.getEndEntityProfileId(),EndEntityProfileAuthorizationProxy.EDIT_RIGHTS)){
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_CHANGEDENDENTITY,"Administrator not authorized to change status");                 
                throw new AuthorizationDeniedException("Administrator not authorized to edit user.");              
            }    
          }
          catch(FinderException e){
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_CHANGEDENDENTITY,"Couldn't find username in database.");    
            throw new EJBException(e.getMessage());            
          }    
        }      

        // Find user
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data = home.findByPrimaryKey(pk);
        data.setStatus(status);
        data.setTimeModified((new java.util.Date()).getTime());        
        logsession.log(admin, LogEntry.MODULE_RA,  new java.util.Date(),username, null, LogEntry.EVENT_INFO_CHANGEDENDENTITY,("New status : " + status));        
        debug("<setUserStatus("+username+", "+status+")");
    } // setUserStatus

   /**
    * Implements IUserAdminSession::setPassword.
    * Implements a mechanism that uses UserData Entity Bean.
    */
    public void setPassword(String username, String password) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException, RemoteException{
        debug(">setPassword("+username+", hiddenpwd)");
        // Find user
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data = home.findByPrimaryKey(pk);

        if(globalconfiguration.getEnableEndEntityProfileLimitations()){
          // Check if user fulfills it's profile.
          EndEntityProfile profile = raadminsession.getEndEntityProfile(data.getEndEntityProfileId());

          boolean fullfillsprofile = true;
          if(profile.isModifyable(EndEntityProfile.PASSWORD,0)){
            if(!password.equals(profile.getValue(EndEntityProfile.PASSWORD,0)));
              fullfillsprofile=false;
          }
          else
            if(profile.isRequired(EndEntityProfile.PASSWORD,0)){
              if(password == null || password.trim().equals(""))
                fullfillsprofile=false;
            }
          if(!fullfillsprofile){
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_CHANGEDENDENTITY,"Password didn't fulfill end entity profile.");  
            throw new UserDoesntFullfillEndEntityProfile("Password didn't fulfill end entity profile.");  
          }  

          // Check if administrator is authorized to edit user.

          if(!profileauthproxy.getEndEntityProfileAuthorization(data.getEndEntityProfileId(),EndEntityProfileAuthorizationProxy.EDIT_RIGHTS)){
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_CHANGEDENDENTITY,"Administrator isn't authorized to change password.");               
            throw new AuthorizationDeniedException("Administrator not authorized to edit user.");          
          }  
        }
        try {
            data.setPassword(password);
            data.setTimeModified((new java.util.Date()).getTime());
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_CHANGEDENDENTITY,"Password changed.");              
        } catch (java.security.NoSuchAlgorithmException nsae)
        {
            debug("NoSuchAlgorithmException while setting password for user "+username);
            throw new EJBException(nsae);
        }
        debug("<setPassword("+username+", hiddenpwd)");
    } // setPassword

   /**
    * Implements IUserAdminSession::setClearTextPassword.
    * Implements a mechanism that uses UserData Entity Bean.
    */
    public void setClearTextPassword(String username, String password) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException,FinderException, RemoteException{
        debug(">setClearTextPassword("+username+", hiddenpwd)");
        // Find user
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data = home.findByPrimaryKey(pk);
        if(globalconfiguration.getEnableEndEntityProfileLimitations()){
          // Check if user fulfills it's profile.
          EndEntityProfile profile = raadminsession.getEndEntityProfile(data.getEndEntityProfileId());
       
          if(profile.isRequired(EndEntityProfile.CLEARTEXTPASSWORD,0) && profile.getValue(EndEntityProfile.CLEARTEXTPASSWORD,0).equals(EndEntityProfile.FALSE)){
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_CHANGEDENDENTITY,"Clearpassword didn't fullfill end entity profile.");                
            throw new UserDoesntFullfillEndEntityProfile("Clearpassword didn't fullfill end entity profile.");   
          }  
          // Check if administrator is authorized to edit user.
          if(!profileauthproxy.getEndEntityProfileAuthorization(data.getEndEntityProfileId(),EndEntityProfileAuthorizationProxy.EDIT_RIGHTS)){
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_CHANGEDENDENTITY,"Administrator isn't authorized to change clearpassword.");               
            throw new AuthorizationDeniedException("Administrator not authorized to edit user.");          
          }  
        }                
        try {
            if (password == null){
                data.setClearPassword("");
                data.setTimeModified((new java.util.Date()).getTime());
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_CHANGEDENDENTITY,"Clearpassword changed.");                     
            }    
            else{
                data.setOpenPassword(password);
                data.setTimeModified((new java.util.Date()).getTime());
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_CHANGEDENDENTITY,"Clearpassword changed.");                     
            }    
        } catch (java.security.NoSuchAlgorithmException nsae)
        {
            debug("NoSuchAlgorithmException while setting password for user "+username);
            throw new EJBException(nsae);
        }
        debug("<setClearTextPassword("+username+", hiddenpwd)");
    } // setClearTextPassword

    /**
     * Method that revokes a user.
     *
     * @param username, the username to revoke.
     */
    public void revokeUser(String username, int reason) throws AuthorizationDeniedException,FinderException, RemoteException{
        debug(">revokeUser("+username+")");
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data;
        try {
            data = home.findByPrimaryKey(pk);
        } catch (ObjectNotFoundException oe) {
            throw new EJBException(oe);            
        }        
         
        if(globalconfiguration.getEnableEndEntityProfileLimitations()){ 
          if(!profileauthproxy.getEndEntityProfileAuthorization(data.getEndEntityProfileId(),EndEntityProfileAuthorizationProxy.REVOKE_RIGHTS)){
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_REVOKEDENDENTITY,"Administrator not authorized");           
            throw new AuthorizationDeniedException("Not authorized to revoke user : " + username + ".");
          }
        }  
        setUserStatus(username, UserDataRemote.STATUS_REVOKED);
        certificatesession.setRevokeStatus(data.getSubjectDN(), reason);
        logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_REVOKEDENDENTITY,"");    
        debug("<revokeUser()");
    } // revokeUser

    /**
    * Implements IUserAdminSession::findUser.
    */
    public UserAdminData findUser(String username) throws FinderException, AuthorizationDeniedException, RemoteException {
        debug(">findUser("+username+")");
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data;
        try {
            data = home.findByPrimaryKey(pk);
        } catch (ObjectNotFoundException oe) {
            return null;
        }

        if(globalconfiguration.getEnableEndEntityProfileLimitations()){
          // Check if administrator is authorized to view user.
          if(!profileauthproxy.getEndEntityProfileAuthorization(data.getEndEntityProfileId(),EndEntityProfileAuthorizationProxy.VIEW_RIGHTS))
            throw new AuthorizationDeniedException("Administrator not authorized to view user.");
        }

        UserAdminData ret = new UserAdminData(data.getUsername(), data.getSubjectDN(), data.getSubjectAltName() ,data.getSubjectEmail(), data.getStatus()
                                        , data.getType(), data.getEndEntityProfileId(), data.getCertificateProfileId()
                                        , new java.util.Date(data.getTimeCreated()), new java.util.Date(data.getTimeModified())
                                        , data.getTokenType(), data.getHardTokenIssuerId());
        ret.setPassword(data.getClearPassword());
        debug("<findUser("+username+")");
        return ret;
    } // findUser

   /**
    * Implements IUserAdminSession::findUserBySubjectDN.
    */
    public UserAdminData findUserBySubjectDN(String subjectdn) throws AuthorizationDeniedException, RemoteException {
        debug(">findUserBySubjectDN("+subjectdn+")");
        String dn = CertTools.stringToBCDNString(subjectdn);
        debug("Looking for users with subjectdn: " + dn);
        UserAdminData returnval = null;

        UserDataLocal data = null;
        try{
          data = home.findBySubjectDN(dn);
        } catch( FinderException e) {
            cat.debug("Cannot find user with DN='"+dn+"'");
        }
        if(globalconfiguration.getEnableEndEntityProfileLimitations()){
          // Check if administrator is authorized to view user.
          if(!profileauthproxy.getEndEntityProfileAuthorization(data.getEndEntityProfileId(),EndEntityProfileAuthorizationProxy.VIEW_RIGHTS))
             throw new AuthorizationDeniedException("Administrator not authorized to view user.");
          }

        if(data != null){
          returnval = new UserAdminData(data.getUsername(), data.getSubjectDN(), data.getSubjectAltName() ,data.getSubjectEmail(), data.getStatus()
                                        , data.getType(), data.getEndEntityProfileId(), data.getCertificateProfileId()
                                        , new java.util.Date(data.getTimeCreated()), new java.util.Date(data.getTimeModified())
                                        , data.getTokenType(), data.getHardTokenIssuerId());
       
          returnval.setPassword(data.getClearPassword());
        }
        debug("<findUserBySubjectDN("+subjectdn+")");
        return returnval;
    } // findUserBySubjectDN

   /**
    * Implements IUserAdminSession::findUserBySubjectDN.
    */
    public UserAdminData findUserByEmail(String email) throws AuthorizationDeniedException, RemoteException {
        debug(">findUserByEmail("+email+")");
        debug("Looking for user with email: " + email);
        UserAdminData returnval = null;

        UserDataLocal data = null;
        try{
          data = home.findBySubjectEmail(email);
        } catch( FinderException e) {
            cat.debug("Cannot find user with Email='"+email+"'");
        }
        if(globalconfiguration.getEnableEndEntityProfileLimitations()){
          // Check if administrator is authorized to view user.
          if(!profileauthproxy.getEndEntityProfileAuthorization(data.getEndEntityProfileId(),EndEntityProfileAuthorizationProxy.VIEW_RIGHTS))
             throw new AuthorizationDeniedException("Administrator not authorized to view user.");
          }

        if(data != null){
          returnval =new UserAdminData(data.getUsername(), data.getSubjectDN(), data.getSubjectAltName() ,data.getSubjectEmail(), data.getStatus()
                                        , data.getType(), data.getEndEntityProfileId(), data.getCertificateProfileId()
                                        , new java.util.Date(data.getTimeCreated()), new java.util.Date(data.getTimeModified())
                                        , data.getTokenType(), data.getHardTokenIssuerId());
          returnval.setPassword(data.getClearPassword());
        }
        debug("<findUserByEmail("+email+")");
        return returnval;
    } // findUserBySubjectDN

   /**
    * Implements IUserAdminSession::CheckIfSubjectDNisAdmin.
    */
    public void checkIfSubjectDNisAdmin(String subjectdn) throws AuthorizationDeniedException, RemoteException {
        debug(">CheckIfSubjectDNisAdmin("+subjectdn+")");
        String dn = CertTools.stringToBCDNString(subjectdn);
        debug("Looking for users with subjectdn: " + dn);
        UserAdminData returnval = null;

        UserDataLocal data = null;
        try{
          data = home.findBySubjectDN(dn);
        } catch( FinderException e) {
          cat.debug("Cannot find user with DN='"+dn+"'");
        }


        if(data != null){
          int type = data.getType();
          if( (type & SecConst.USER_ADMINISTRATOR)  == 0){ 
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_ADMINISTRATORLOGGEDIN,"Certificate didn't belong to an administrator."); 
            throw new  AuthorizationDeniedException("Your certificate do not belong to an administrator.");
          }  
        }else{
          logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_ADMINISTRATORLOGGEDIN,"Certificate didn't belong to any user.");  
          throw new  AuthorizationDeniedException("Your certificate do not belong to any user.");
        }


        debug("<CheckIfSubjectDNisAdmin("+subjectdn+")");
    } // findUserBySubjectDN


    /**
    * Implements IUserAdminSession::findAllUsersByStatus.
    */
    public Collection findAllUsersByStatus(int status) throws FinderException, RemoteException {
        debug(">findAllUsersByStatus("+status+")");
        debug("Looking for users with status: " + status);
        Collection users = home.findByStatus(status);
        Collection ret = new ArrayList();
        Iterator iter = users.iterator();
        while (iter.hasNext())
        {
            UserDataLocal user = (UserDataLocal) iter.next();
            UserAdminData userData = new UserAdminData(user.getUsername(), user.getSubjectDN(), user.getSubjectAltName() ,user.getSubjectEmail(), user.getStatus()
                                        , user.getType(), user.getEndEntityProfileId(), user.getCertificateProfileId()
                                        , new java.util.Date(user.getTimeCreated()), new java.util.Date(user.getTimeModified())
                                        , user.getTokenType(), user.getHardTokenIssuerId());
            userData.setPassword(user.getClearPassword());
            if(globalconfiguration.getEnableEndEntityProfileLimitations()){
              // Check if administrator is authorized to view user.
              if(profileauthproxy.getEndEntityProfileAuthorization(user.getEndEntityProfileId(),EndEntityProfileAuthorizationProxy.VIEW_RIGHTS))
                ret.add(userData);
            }
            else
              ret.add(userData);
        }
        debug("found "+ret.size()+" user(s) with status="+status);
        debug("<findAllUsersByStatus("+status+")");
        return ret;
    } // findAllUsersByStatus

    /**
    * Implements IUserAdminSession::findAllUsersWithLimit.
    */
    public Collection findAllUsersWithLimit()  throws FinderException, RemoteException{
        debug(">findAllUsersWithLimit()");
        Collection users = home.findAll();
        Collection ret = new ArrayList();
        Iterator iter = users.iterator();
        while (iter.hasNext() && (ret.size() <= IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT ))
        {
            UserDataLocal user = (UserDataLocal) iter.next();
            UserAdminData userData =  new UserAdminData(user.getUsername(), user.getSubjectDN(), user.getSubjectAltName() ,user.getSubjectEmail(), user.getStatus()
                                        , user.getType(), user.getEndEntityProfileId(), user.getCertificateProfileId()
                                        , new java.util.Date(user.getTimeCreated()), new java.util.Date(user.getTimeModified())
                                        , user.getTokenType(), user.getHardTokenIssuerId());
            userData.setPassword(user.getClearPassword());
            if(globalconfiguration.getEnableEndEntityProfileLimitations()){
              // Check if administrator is authorized to view user.
              if(profileauthproxy.getEndEntityProfileAuthorization(user.getEndEntityProfileId(),EndEntityProfileAuthorizationProxy.VIEW_RIGHTS))
                ret.add(userData);
            }
            else
              ret.add(userData);
        }
        debug("<findAllUsersWithLimit()");
        return ret;
    }

   /**
    * Implements IUserAdminSession::startExternalService.
    */
    public void startExternalService( String[] args ) {
        debug(">startService()");
        try {
            RMIFactory rmiFactory = (RMIFactory)Class.forName(
                (String)lookup("java:comp/env/RMIFactory",
                               java.lang.String.class)
                ).newInstance();
            rmiFactory.startConnection( args );
            debug(">startService()");
        } catch( Exception e ) {
            error("Lyckades inte starta extern service.", e);
            throw new EJBException("Error starting external service", e);
        }
    } // startExternalService

    /**
     * Method to execute a customized query on the ra user data. The parameter query should be a legal Query object.
     *
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     * @return a collection of UserAdminData. Maximum size of Collection is defined i IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @see se.anatom.ejbca.util.query.Query
     */
    public Collection query(Query query) throws IllegalQueryException, RemoteException{
        debug(">query()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        ArrayList returnval = new ArrayList();

        // Check if query is legal.
        if(!query.isLegalQuery())
          throw new IllegalQueryException();
        try{
           // Construct SQL query.
            con = getConnection();        
            ps = con.prepareStatement("select " + USERDATA_COL + " from UserData where " + query.getQueryString());
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            while(rs.next() && returnval.size() <= IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT){
              UserAdminData data = new UserAdminData(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getInt(5), rs.getInt(6)
                                               , rs.getInt(10), rs.getInt(11)
                                               , new java.util.Date(rs.getLong(8)), new java.util.Date(rs.getLong(9))
                                               ,  rs.getInt(12), rs.getInt(13));            
              data.setPassword(rs.getString(7));

              if(globalconfiguration.getEnableEndEntityProfileLimitations()){
                // Check if administrator is authorized to edit user.
                if(profileauthproxy.getEndEntityProfileAuthorization(data.getEndEntityProfileId(),EndEntityProfileAuthorizationProxy.VIEW_RIGHTS))
                  returnval.add(data);
              }
              else
                returnval.add(data);
            }
            debug("<query()");
            return returnval;

        }catch(Exception e){
          throw new EJBException(e);
        }finally{
           try{
             if(rs != null) rs.close();
             if(ps != null) ps.close();
             if(con!= null) con.close();
           }catch(SQLException se){
              se.printStackTrace();
           }
        }
    } // query

    /**
     * Methods that checks if a user exists in the database having the given endentityprofileid. This function is mainly for avoiding
     * desyncronisation when a end entity profile is deleted.
     *
     * @param endentityprofileid the id of end entity profile to look for.
     * @return true if endentityprofileid exists in userdatabase.
     */
    public boolean checkForEndEntityProfileId(int endentityprofileid){
        debug(">checkForEndEntityProfileId()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        ArrayList returnval = new ArrayList();
        int count = 1; // return true as default.

        Query query = new Query(Query.TYPE_USERQUERY);
        query.add(UserMatch.MATCH_WITH_ENDENTITYPROFILE, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(endentityprofileid));

        try{
           // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select COUNT(*) from UserData where " + query.getQueryString());
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            while(rs.next()){
              count = rs.getInt(1);
            }
            debug("<checkForEndEntityProfileId()");
            return count > 0;

        }catch(Exception e){
          throw new EJBException(e);
        }finally{
           try{
             if(rs != null) rs.close();
             if(ps != null) ps.close();
             if(con!= null) con.close();
           }catch(SQLException se){
              se.printStackTrace();
           }
        }


    }

    /**
     * Methods that checks if a user exists in the database having the given certificateprofileid. This function is mainly for avoiding
     * desyncronisation when a certificateprofile is deleted.
     *
     * @param certificateprofileid the id of certificateprofile to look for.
     * @return true if certificateproileid exists in userdatabase.
     */
    public boolean checkForCertificateProfileId(int certificateprofileid){
        debug(">checkForCertificateProfileId()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        ArrayList returnval = new ArrayList();
        int count = 1; // return true as default.

        Query query = new Query(Query.TYPE_USERQUERY);
        query.add(UserMatch.MATCH_WITH_CERTIFICATEPROFILE, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(certificateprofileid));

        try{
           // Construct SQL query.
            con = getConnection();
            ps = con.prepareStatement("select COUNT(*) from UserData where " + query.getQueryString());
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            while(rs.next()){
              count = rs.getInt(1);
            }
            debug("<checkForCertificateProfileId()");
            return count > 0;

        }catch(Exception e){
          throw new EJBException(e);
        }finally{
           try{
             if(rs != null) rs.close();
             if(ps != null) ps.close();
             if(con!= null) con.close();
           }catch(SQLException se){
              se.printStackTrace();
           }
        }
    } // checkForCertificateProfileId

     /**
     * Loads the global configuration from the database.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public GlobalConfiguration loadGlobalConfiguration()  {
        debug(">loadGlobalConfiguration()");
        GlobalConfiguration ret=null;
        try{
          GlobalConfigurationDataLocal gcdata = globalconfigurationhome.findByPrimaryKey("0");
          if(gcdata!=null){
            ret = gcdata.getGlobalConfiguration();
          }
        }catch (javax.ejb.FinderException fe) {
             // Create new configuration
             ret = new GlobalConfiguration();
        }
        debug("<loadGlobalConfiguration()");
        return ret;
    } //loadGlobalConfiguration

    /**
     * Saves global configuration to the database.
     *
     * @throws EJBException if a communication or other error occurs.
     */

    public void saveGlobalConfiguration( GlobalConfiguration globalconfiguration)  {
        debug(">saveGlobalConfiguration()");
        String pk = "0";
        try {
          GlobalConfigurationDataLocal gcdata = globalconfigurationhome.findByPrimaryKey(pk);
          gcdata.setGlobalConfiguration(globalconfiguration);
          try{
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITSYSTEMCONFIGURATION,"");    
          }catch(RemoteException re){}  
        }catch (javax.ejb.FinderException fe) {
           // Global configuration doesn't yet exists.
           try{
             GlobalConfigurationDataLocal data1= globalconfigurationhome.create(pk,globalconfiguration);
             try{
               logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_EDITSYSTEMCONFIGURATION,"");    
             }catch(RemoteException re){}              
           } catch(CreateException e){
             try{   
               logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_EDITSYSTEMCONFIGURATION,"");   
             }catch(RemoteException re){} 
           }
        }
        this.globalconfiguration=globalconfiguration;
        debug("<saveGlobalConfiguration()");
     } // saveGlobalConfiguration

   private int makeType(boolean administrator, boolean keyrecoverable){
     int returnval = SecConst.USER_ENDUSER;
     if(administrator)
       returnval += SecConst.USER_ADMINISTRATOR;
     if(keyrecoverable)
       returnval += SecConst.USER_KEYRECOVERABLE;
       
     return returnval;  
   } // makeType
    
} // LocalUserAdminSessionBean

