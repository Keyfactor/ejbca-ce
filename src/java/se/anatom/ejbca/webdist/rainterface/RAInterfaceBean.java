
/*
 * RaInterfaceBean.java
 *
 * Created on den 12 april 2002, 14:36
 */

package se.anatom.ejbca.webdist.rainterface;

import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;
import java.util.Properties;
import java.util.Collection;
import java.util.Iterator;
import java.util.Vector;
import java.util.HashMap;
import java.io.Serializable;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.math.BigInteger;

import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.CertificateDataPK;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.store.CertificateDataHome;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ra.UserDataRemote;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Hex;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;
import se.anatom.ejbca.ra.raadmin.EndEntityProfileExistsException;
import se.anatom.ejbca.ra.raadmin.EndEntityProfileDoesntExistsException;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import se.anatom.ejbca.ra.authorization.AdminInformation;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.authorization.EndEntityProfileAuthorizationProxy;
import se.anatom.ejbca.ra.authorization.IAuthorizationSessionHome;
import se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote;
import se.anatom.ejbca.util.query.*;
import se.anatom.ejbca.webdist.cainterface.CertificateProfileNameProxy;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.SecConst;

/**
 * A java bean handling the interface between EJBCA ra module and JSP pages.
 *
 * @author  Philip Vendil
 * @version $Id: RAInterfaceBean.java,v 1.15 2002-10-24 20:13:06 herrvendil Exp $
 */
public class RAInterfaceBean {

    // Public constants.
    public static final int MAXIMUM_QUERY_ROWCOUNT = IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT;
    
    public static final String[] tokentexts = {"TOKENSOFTBROWSERGEN","TOKENSOFTP12","TOKENSOFTJKS","TOKENSOFTPEM"};
    public static final int[]    tokenids   = {SecConst.TOKEN_SOFT_BROWSERGEN,SecConst.TOKEN_SOFT_P12,SecConst.TOKEN_SOFT_JKS,SecConst.TOKEN_SOFT_PEM};

    /** Creates new RaInterfaceBean */
    public RAInterfaceBean() throws  IOException, NamingException, FinderException, CreateException  {  
      users = new UsersView();
      addedusermemory = new AddedUserMemory();
    }
    // Public methods.
    public void initialize(HttpServletRequest request) throws  Exception{

      if(!initialized){
        administrator = new Admin(((X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" ))[0]);  
        // Get the UserAdminSession instance.
        
        jndicontext = new InitialContext();
        Object obj1 = jndicontext.lookup("UserAdminSession");
        adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
        adminsession = adminsessionhome.create(administrator);
      
        obj1 = jndicontext.lookup("RaAdminSession");
        raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"), 
                                                                                 IRaAdminSessionHome.class);
        raadminsession = raadminsessionhome.create(administrator); 
        this.profiles = new EndEntityProfileDataHandler(administrator);    
        
        obj1 =  jndicontext.lookup("CertificateStoreSession");   
        certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
        certificatesession = certificatesessionhome.create(administrator);
        
        obj1 = jndicontext.lookup("AuthorizationSession");
        IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("AuthorizationSession"),
                                                                                 IAuthorizationSessionHome.class);
        globalconfiguration = adminsession.loadGlobalConfiguration();        
        authorizationsession = authorizationsessionhome.create(globalconfiguration, administrator);

        
        profileauthproxy = new EndEntityProfileAuthorizationProxy(administrator.getAdminInformation(), authorizationsession);
        certprofilenameproxy = new CertificateProfileNameProxy(administrator);    
        profilenameproxy = new EndEntityProfileNameProxy(administrator);  
        initialized =true; 
      }
    }

    /* Adds a user to the database, the string array must be in format defined in class UserView. */
    public void addUser(UserView userdata) throws Exception{
    
         if(userdata.getEndEntityProfileId() != 0){
           adminsession.addUser(userdata.getUsername(), userdata.getPassword(), userdata.getSubjectDN(), userdata.getSubjectAltName()
                               ,userdata.getEmail(), userdata.getClearTextPassword(), userdata.getEndEntityProfileId(),
                                userdata.getCertificateProfileId(), userdata.getAdministrator(),
                                userdata.getKeyRecoverable(), userdata.getTokenType(), userdata.getHardTokenIssuerId());
           addedusermemory.addUser(userdata);

        }  
    }

    /* Removes a number of users from the database. 
     *
     * @param usernames an array of usernames to delete.
     * @return false if administrator wasn't authorized to delete all of given users.
     * */
    public boolean deleteUsers(String[] usernames) throws Exception{
      boolean success = true;
      for(int i=0; i < usernames.length; i++){
         try{ 
           adminsession.deleteUser(usernames[i]);
         }catch(AuthorizationDeniedException e){
           success = false;   
         }
      }
      return success;   
    }
      
    /* Changes the status of a number of users from the database. 
     *
     * @param usernames an array of usernames to change.
     * @param status gives the status to apply to users, should be one of UserDataRemote.STATUS constants.
     * @return false if administrator wasn't authorized to change all of the given users.
     * */
    public boolean setUserStatuses(String[] usernames, String status) throws Exception{
      boolean success = true;  
      int intstatus = 0;
      try{
        intstatus = Integer.parseInt(status);
      }catch(Exception e){}
      for(int i=0; i < usernames.length; i++){
        try{  
          adminsession.setUserStatus(usernames[i],intstatus);
        }catch(AuthorizationDeniedException e){
           success = false;   
        }
      }
      return success;
    }

    /** Revokes the the given users.
     *
     * @param users an array of usernames to revoke.
     * @param reason reason(s) of revokation.
     * @return false if administrator wasn't authorized to revoke all of the given users.
     */
    public boolean revokeUsers(String[] usernames, int reason) throws  Exception{
      boolean success = true;
      for(int i=0; i < usernames.length; i++){
        try{
          adminsession.revokeUser( usernames[i], reason); 
        }catch( AuthorizationDeniedException e){
          success =false;   
        }
      } 
      return success;
    }

    /* Changes the userdata  */
    public void changeUserData(UserView userdata) throws Exception {
        int profileid = userdata.getEndEntityProfileId();
        int certificatetypeid =userdata.getCertificateProfileId();    
        
        addedusermemory.changeUser(userdata);
        adminsession.changeUser(userdata.getUsername(), userdata.getSubjectDN(), userdata.getSubjectAltName()
                                   ,userdata.getEmail(),  userdata.getEndEntityProfileId(),
                                    userdata.getCertificateProfileId(), userdata.getAdministrator(),
                                    userdata.getKeyRecoverable(), userdata.getTokenType(), userdata.getHardTokenIssuerId());
          // if ra admin have chosen to store the password as cleartext.
         if(userdata.getPassword() != null && !userdata.getPassword().trim().equals("")){
           if(userdata.getClearTextPassword()){  
             adminsession.setClearTextPassword(userdata.getUsername(), userdata.getPassword());
           }
           else{
             adminsession.setPassword(userdata.getUsername(), userdata.getPassword());             
           }
         }  
    }

    /* Method to filter out a user by it's username */
    public UserView[] filterByUsername(String username) throws RemoteException, NamingException, FinderException, CreateException{
       UserAdminData[] userarray = new UserAdminData[1];
       UserAdminData user = null;
       try{
         user = adminsession.findUser(username);
       }catch(AuthorizationDeniedException e){  
       }
         
       if(user != null){
         userarray[0]=user;
         users.setUsers(userarray);
       }else{
         users.setUsers((UserAdminData[]) null);
       }

       return users.getUsers(0,1);
    }

    /* Method used to check if user exists */
    public boolean userExist(String username) throws RemoteException, NamingException, FinderException, CreateException{
       UserAdminData user =null;
       try{
         user = adminsession.findUser(username);
       }catch(AuthorizationDeniedException e){  
       }        
        
      return user != null;
    }

    /* Method to retrieve a user from the database without inserting it into users data, used by 'viewuser.jsp' and page*/
    public UserView findUser(String username) throws RemoteException, NamingException, FinderException, CreateException, AuthorizationDeniedException{

       UserAdminData user = adminsession.findUser(username);
       if(user != null){
         UserView userview = new UserView(user);         
         return userview;
       }  
       else
         return null;  

    } 
    /* Method to retrieve a user from the database without inserting it into users data, used by 'edituser.jsp' and page*/
    public UserView findUserForEdit(String username) throws RemoteException, NamingException, FinderException, CreateException, AuthorizationDeniedException{

       UserAdminData user = adminsession.findUser(username);
       if(globalconfiguration.getEnableEndEntityProfileLimitations())
         if(!profileauthproxy.getEndEntityProfileAuthorization(user.getEndEntityProfileId(),EndEntityProfileAuthorizationProxy.EDIT_RIGHTS))     
           throw new AuthorizationDeniedException("Not Authorized to edit user.");
       
       UserView userview = new UserView(user); 
       return userview;

    } 
    
    /* Method to find all users in database */
    public UserView[] findAllUsers(int index,int size) throws RemoteException,FinderException,NamingException,
                                                                                              NumberFormatException,
                                                                                              CreateException{
       users.setUsers(adminsession.findAllUsersWithLimit());
       return users.getUsers(index,size); 
                                                                                                  
    }

    /* Method that checks if a certificate serialnumber is revoked and returns the user(s), else a null value. */
    public UserView[] filterByCertificateSerialNumber(String serialnumber, int index, int size) throws RemoteException,
                                                                                                   FinderException,
                                                                                                   NamingException,
                                                                                                   NumberFormatException,
                                                                                                   CreateException{

      serialnumber = serialnumber.replaceAll(" ","");
      Collection certs =certificatesession.findCertificatesBySerno(new BigInteger(serialnumber,16));
      Vector uservector = new Vector();
      UserView[] returnval = null;
      if(certs != null){
        Iterator iter = certs.iterator();
        while(iter.hasNext()){
           UserAdminData user = null; 
           try{ 
             user = adminsession.findUserBySubjectDN(((X509Certificate) iter.next()).getSubjectDN().toString());
           }catch(AuthorizationDeniedException e){  
             user=null;
           }     
           if(user != null){
             uservector.addElement(user);
           }
        }
        users.setUsers(uservector);

        returnval= users.getUsers(index,size);
      }
      return returnval;
    }

    /* Method that lists all users with certificate's that expires within given days. */
    public UserView[] filterByExpiringCertificates(String days, int index, int size) throws RemoteException,
                                                                                            FinderException,
                                                                                            NumberFormatException,
                                                                                            NamingException,
                                                                                            CreateException{
      Vector uservector = new Vector();
      HashMap addedusers = new HashMap();
      UserView[] returnval = null;

      long d = Long.parseLong(days);
      Date finddate = new Date();
      long millis = (d * 86400000); // One day in milliseconds.
      finddate.setTime(finddate.getTime() + (long)millis);

      Collection certs =certificatesession.findCertificatesByExpireTime(finddate);
      if(!certs.isEmpty()){
        Iterator i = certs.iterator();
        while(i.hasNext() && uservector.size() <= MAXIMUM_QUERY_ROWCOUNT ){
           UserAdminData user = null;
           try{
             user = adminsession.findUserBySubjectDN(((X509Certificate) i.next()).getSubjectDN().toString());
           }catch(AuthorizationDeniedException e){  
             user=null;
           }  
           if(user != null && addedusers.get(user.getUsername()) == null){
             addedusers.put(user.getUsername() ,new Boolean(true));  
             uservector.addElement(user);
           }
        }
        users.setUsers(uservector);

        returnval= users.getUsers(index,size);
      }
      return returnval;
    }

    public UserView[] filterByQuery(Query query, int index, int size) throws Exception {
      Collection uservector = (Collection) adminsession.query(query);
      users.setUsers(uservector);

      return users.getUsers(index,size);        
    }    
    
    public boolean isAuthorizedToViewUserHistory(String username) throws Exception {
      UserAdminData user = adminsession.findUser(username);  
      return profileauthproxy.getEndEntityProfileAuthorization(user.getEndEntityProfileId(),EndEntityProfileAuthorizationProxy.HISTORY_RIGHTS); 
    }   

    /* Method to resort filtered user data. */
    public void sortUserData(int sortby, int sortorder){
      users.sortBy(sortby,sortorder);
    }

    /* Method to return the users between index and size, if userdata is smaller than size, a smaller array is returned. */
    public UserView[] getUsers(int index, int size){
      return users.getUsers(index, size);
    }

    public boolean nextButton(int index, int size){
      return index + size < users.size();
    }
    public boolean previousButton(int index, int size){
      return index > 0 ;
    }
    
    // Method dealing with added user memory.
    /** A method to get the last added users in adduser.jsp.
     *
     * @see se.anatom.ejbca.webdist.rainterface.AddedUserMemory
     */
    public UserView[] getAddedUsers(int size){
      return addedusermemory.getUsers(size);   
    }
    
    // Methods dealing with profiles.

    
    public String[] getEndEntityProfileNames() throws RemoteException{
      return profiles.getEndEntityProfileNames();
    }
    
    /** Returns the profile name from id proxied */
    public String getEndEntityProfileName(int profileid) throws RemoteException{
      return profilenameproxy.getEndEntityProfileName(profileid);
    }
    
    public String[] getCreateAuthorizedEndEntityProfileNames() throws RemoteException{
      Vector result = new Vector();
      String[] profilenames =  profiles.getEndEntityProfileNames();
      String[] dummy = {};
      for(int i =0; i< profilenames.length; i++){
        if(profileauthproxy.getEndEntityProfileAuthorization(profiles.getEndEntityProfileId(profilenames[i]),EndEntityProfileAuthorizationProxy.CREATE_RIGHTS)){
          result.add(profilenames[i]);   
        }
      }
     
      return (String[]) result.toArray(dummy);
    }    
    
    public String[] getEditAuthorizedEndEntityProfileNames() throws RemoteException{
      Vector result = new Vector();
      String[] profilenames =  profiles.getEndEntityProfileNames();
      String[] dummy = {};
      for(int i =0; i< profilenames.length; i++){
        if(profileauthproxy.getEndEntityProfileAuthorization(profiles.getEndEntityProfileId(profilenames[i]),EndEntityProfileAuthorizationProxy.EDIT_RIGHTS)){
          result.add(profilenames[i]);   
        }
      }
     
      return (String[]) result.toArray(dummy);
    }        
    
    public int getEndEntityProfileId(String profilename) throws RemoteException{
      return profiles.getEndEntityProfileId(profilename);   
    }

    /* Returns profiles as a EndEntityProfiles object */
    public EndEntityProfileDataHandler getEndEntityProfileDataHandler(){
      return profiles;
    }

    public EndEntityProfile getEndEntityProfile(String name) throws RemoteException{
      return profiles.getEndEntityProfile(name);
    }
    
    public EndEntityProfile getEndEntityProfile(int id) throws RemoteException{
      return profiles.getEndEntityProfile(id);
    }
    
    public void addEndEntityProfile(String name) throws EndEntityProfileExistsException, RemoteException{
       profiles.addEndEntityProfile(name, new EndEntityProfile());
    }

    public void addEndEntityProfile(String name, EndEntityProfile profile) throws EndEntityProfileExistsException, RemoteException {
       profiles.addEndEntityProfile(name, profile);
    }

    public void changeEndEntityProfile(String name, EndEntityProfile profile) throws EndEntityProfileDoesntExistsException, RemoteException {
       profiles.changeEndEntityProfile(name, profile);
    }

    /* Returns false if profile is used by any user or in authorization rules. */
    public boolean removeEndEntityProfile(String name)throws RemoteException{
        boolean profileused = false;
        int profileid = raadminsession.getEndEntityProfileId(name);
        // Check if any users or authorization rule use the profile.

        profileused = adminsession.checkForEndEntityProfileId(profileid) 
                      || authorizationsession.existsEndEntityProfileInRules(profileid); 

        if(!profileused){
          profiles.removeEndEntityProfile(name);
        }
        
        return !profileused;
    }

    public void renameEndEntityProfile(String oldname, String newname) throws EndEntityProfileExistsException, RemoteException{
       profiles.renameEndEntityProfile(oldname, newname);
    }

    public void cloneEndEntityProfile(String originalname, String newname) throws EndEntityProfileExistsException, RemoteException{
      profiles.cloneEndEntityProfile(originalname, newname);
    }

    public void loadCertificates(String subjectdn) throws RemoteException, NamingException, CreateException, AuthorizationDeniedException, FinderException{
      Collection certs = certificatesession.findCertificatesBySubject(subjectdn);
      
      UserAdminData user = adminsession.findUserBySubjectDN(subjectdn);
      
      if(!certs.isEmpty()){
        Iterator j = certs.iterator();
        certificates = new CertificateView[certs.size()];
        for(int i=0; i< certificates.length; i++){
          RevokedInfoView revokedinfo = null;
          X509Certificate cert = (X509Certificate) j.next();
          RevokedCertInfo revinfo = certificatesession.isRevoked(cert.getIssuerDN().toString(), cert.getSerialNumber());
          if(revinfo != null)
            revokedinfo = new RevokedInfoView(revinfo);
           certificates[i] = new CertificateView(cert, revokedinfo);
        }
      }
      else{
        certificates = null;
      }
    }

    public int getNumberOfCertificates(){
      int returnval=0;
      if(certificates != null){
        returnval=certificates.length;
      }

      return returnval;
    }

    public CertificateView getCertificate(int index){
      CertificateView returnval = null;

      if(certificates != null){
        returnval = certificates[index];
      }

      return returnval;
    }
    
    public boolean authorizedToEditUser(int profileid) throws RemoteException{
      return profileauthproxy.getEndEntityProfileAuthorization(profileid, EndEntityProfileAuthorizationProxy.EDIT_RIGHTS);
    }
    
    public boolean authorizedToViewHistory(int profileid) throws RemoteException{
      return profileauthproxy.getEndEntityProfileAuthorization(profileid, EndEntityProfileAuthorizationProxy.HISTORY_RIGHTS);
    }    
    
    public String[] getCertificateProfileNames() throws RemoteException{
      String[] dummy = {""};
      Collection certprofilenames = certificatesession.getCertificateProfileNames();
      if(certprofilenames == null)
        return new String[0];
      else        
        return (String[]) certprofilenames.toArray(dummy); 
    }
    
    public int getCertificateProfileId(String certificateprofilename) throws RemoteException{
      return certificatesession.getCertificateProfileId(certificateprofilename); 
    }
    public String getCertificateProfileName(int certificateprofileid) throws RemoteException{
      return certprofilenameproxy.getCertificateProfileName(certificateprofileid); 
    }
   
    public boolean getEndEntityParameter(String parameter){
       if(parameter == null)
         return false;
         
       return parameter.equals(EndEntityProfile.TRUE); 
    }
    
    // Private methods.

    // Private fields.

    private EndEntityProfileDataHandler    profiles;

    private InitialContext                 jndicontext;
    private IUserAdminSessionRemote        adminsession;
    private IUserAdminSessionHome          adminsessionhome;
    private ICertificateStoreSessionRemote certificatesession;
    private ICertificateStoreSessionHome   certificatesessionhome;
    private IRaAdminSessionHome            raadminsessionhome;    
    private IRaAdminSessionRemote          raadminsession;  
    private IAuthorizationSessionRemote    authorizationsession;

    private UsersView                      users;
    private CertificateView[]              certificates;
    private AddedUserMemory                addedusermemory;
    private Admin                          administrator;
    private EndEntityProfileAuthorizationProxy      profileauthproxy;
    private CertificateProfileNameProxy       certprofilenameproxy;  
    private EndEntityProfileNameProxy               profilenameproxy;
    private GlobalConfiguration            globalconfiguration;
    private boolean initialized=false;
}
