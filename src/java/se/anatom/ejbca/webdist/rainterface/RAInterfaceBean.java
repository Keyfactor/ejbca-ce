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
import se.anatom.ejbca.ra.raadmin.Profile;
import se.anatom.ejbca.ra.raadmin.ProfileExistsException;
import se.anatom.ejbca.ra.raadmin.ProfileDoesntExistsException;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillProfile;
import se.anatom.ejbca.ra.authorization.UserInformation;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.authorization.ProfileAuthorizationProxy;
import se.anatom.ejbca.ra.authorization.IAuthorizationSessionHome;
import se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote;
import se.anatom.ejbca.util.query.*;
import se.anatom.ejbca.webdist.cainterface.CertificateTypeNameProxy;
import se.anatom.ejbca.log.Admin;

/**
 * A java bean handling the interface between EJBCA ra module and JSP pages.
 *
 * @author  Philip Vendil
 * @version $Id: RAInterfaceBean.java,v 1.14 2002-09-12 18:14:15 herrvendil Exp $
 */
public class RAInterfaceBean {

    // Public constants.
    public static final int MAXIMUM_QUERY_ROWCOUNT = IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT;

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
        this.profiles = new ProfileDataHandler(administrator);    
        
        obj1 =  jndicontext.lookup("CertificateStoreSession");   
        certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
        certificatesession = certificatesessionhome.create(administrator);
        
        obj1 = jndicontext.lookup("AuthorizationSession");
        IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("AuthorizationSession"),
                                                                                 IAuthorizationSessionHome.class);
        globalconfiguration = adminsession.loadGlobalConfiguration();        
        authorizationsession = authorizationsessionhome.create(globalconfiguration, administrator);

        
        profileauthproxy = new ProfileAuthorizationProxy(administrator.getUserInformation(), authorizationsession);
        certtypenameproxy = new CertificateTypeNameProxy(administrator);    
        profilenameproxy = new ProfileNameProxy(administrator);  
        initialized =true; 
      }
    }

    /* Adds a user to the database, the string array must be in format defined in class UserView. */
    public void addUser(String[] stringuserdata) throws Exception{
        // lookup profileid and certificatetype id;
        if(stringuserdata[UserView.PROFILE] != null){
          if(stringuserdata[UserView.PROFILE].trim() != ""){
            int profileid =  Integer.parseInt(stringuserdata[UserView.PROFILE]);
            int certificatetypeid = Integer.parseInt(stringuserdata[UserView.CERTIFICATETYPE]);
            boolean clearpwd = false;
            // if ra admin have chosen to store the password as cleartext.
            if(stringuserdata[UserView.CLEARTEXTPASSWORD] != null && stringuserdata[UserView.CLEARTEXTPASSWORD].equals(UserView.TRUE)){
              clearpwd = true;
            }            
            if(profileid != 0){
              UserView userview =  new UserView(stringuserdata,null,null);
              UserAdminData user = userview.convertToUserAdminData();
              adminsession.addUser(user.getUsername(), user.getPassword(), user.getDN(), user.getEmail()
                                   ,user.getType(),clearpwd,profileid, certificatetypeid);
              addedusermemory.addUser(userview);

            }
          }
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
    public void changeUserData(String[] userdata) throws Exception {
        int profileid = UserAdminData.NO_PROFILE;
        int certificatetypeid = UserAdminData.NO_CERTIFICATETYPE;    
        // lookup profileid and certificatetype id;
        if(userdata[UserView.PROFILE] != null){
          if(userdata[UserView.PROFILE].trim() != ""){
             profileid =  Integer.parseInt(userdata[UserView.PROFILE]);
          }
        }
        if(userdata[UserView.CERTIFICATETYPE] != null){
          if(userdata[UserView.CERTIFICATETYPE].trim() != ""){
             certificatetypeid = Integer.parseInt(userdata[UserView.CERTIFICATETYPE]);
          }
        }
        
        UserView userview = new UserView(userdata,null,null);
        UserAdminData user = userview.convertToUserAdminData();
        addedusermemory.changeUser(userview);
        adminsession.changeUser(user.getUsername(),  user.getDN(), user.getEmail(),user.getType(), profileid, certificatetypeid);
          // if ra admin have chosen to store the password as cleartext.
         if(user.getPassword() != null && !user.getPassword().trim().equals("")){
           if(userdata[UserView.CLEARTEXTPASSWORD] != null && userdata[UserView.CLEARTEXTPASSWORD].equals(UserView.TRUE)){  
             adminsession.setClearTextPassword(user.getUsername(), user.getPassword());
           }
           else{
             adminsession.setPassword(user.getUsername(), user.getPassword());             
           }
         }  
    }

    /* Method to filter out a user by it's username */
    public String[][] filterByUsername(String username) throws RemoteException, NamingException, FinderException, CreateException{
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
       UserView userview = new UserView(user); 
       return userview;

    } 
    /* Method to retrieve a user from the database without inserting it into users data, used by 'edituser.jsp' and page*/
    public UserView findUserForEdit(String username) throws RemoteException, NamingException, FinderException, CreateException, AuthorizationDeniedException{

       UserAdminData user = adminsession.findUser(username);
       if(globalconfiguration.getUseStrongAuthorization())
         if(!profileauthproxy.getProfileAuthorization(user.getProfileId(),ProfileAuthorizationProxy.EDIT_RIGHTS))     
           throw new AuthorizationDeniedException("Not Authorized to edit user.");
       
       UserView userview = new UserView(user); 
       return userview;

    } 
    
    /* Method to find all users in database */
    public String[][] findAllUsers(int index,int size) throws RemoteException,FinderException,NamingException,
                                                                                              NumberFormatException,
                                                                                              CreateException{
       users.setUsers(adminsession.findAllUsersWithLimit());
       return users.getUsers(index,size); 
                                                                                                  
    }

    /* Method that checks if a certificate serialnumber is revoked and returns the user(s), else a null value. */
    public String[][] filterByCertificateSerialNumber(String serialnumber, int index, int size) throws RemoteException,
                                                                                                   FinderException,
                                                                                                   NamingException,
                                                                                                   NumberFormatException,
                                                                                                   CreateException{

      serialnumber = serialnumber.replaceAll(" ","");
      Collection certs =certificatesession.findCertificatesBySerno(new BigInteger(serialnumber,16));
      Vector uservector = new Vector();
      String[][] returnval = null;
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
    public String[][] filterByExpiringCertificates(String days, int index, int size) throws RemoteException,
                                                                                            FinderException,
                                                                                            NumberFormatException,
                                                                                            NamingException,
                                                                                            CreateException{
      Vector uservector = new Vector();
      HashMap addedusers = new HashMap();
      String[][] returnval = null;

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

    public String[][] filterByQuery(Query query, int index, int size) throws Exception {
      Collection uservector = (Collection) adminsession.query(query);
      users.setUsers(uservector);

      return users.getUsers(index,size);        
    }    
    
    public boolean isAuthorizedToViewUserHistory(String username) throws Exception {
      UserAdminData user = adminsession.findUser(username);  
      return profileauthproxy.getProfileAuthorization(user.getProfileId(),ProfileAuthorizationProxy.HISTORY_RIGHTS); 
    }   

    /* Method to resort filtered user data. */
    public void sortUserData(int sortby, int sortorder){
      users.sortBy(sortby,sortorder);
    }

    /* Method to return the users between index and size, if userdata is smaller than size, a smaller array is returned. */
    public String[][] getUsers(int index, int size){
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
    public String[][] getAddedUsers(int size){
      return addedusermemory.getUsers(size);   
    }
    
    // Methods dealing with profiles.
    /** Returns all profile data as strings. The commonly used method in ra jsp pages.*/
    public String[][][] getProfilesAsString() throws RemoteException{
      return profiles.getProfilesAsStrings();
    }

    public String[] getProfileNames() throws RemoteException{
      return profiles.getProfileNames();
    }
    
    /** Returns the profile name from id proxied */
    public String getProfileName(int profileid) throws RemoteException{
      return profilenameproxy.getProfileName(profileid);
    }
    
    public String[] getCreateAuthorizedProfileNames() throws RemoteException{
      Vector result = new Vector();
      String[] profilenames =  profiles.getProfileNames();
      String[] dummy = {};
      for(int i =0; i< profilenames.length; i++){
        if(profileauthproxy.getProfileAuthorization(profiles.getProfileId(profilenames[i]),ProfileAuthorizationProxy.CREATE_RIGHTS)){
          result.add(profilenames[i]);   
        }
      }
     
      return (String[]) result.toArray(dummy);
    }    
    
    public String[] getEditAuthorizedProfileNames() throws RemoteException{
      Vector result = new Vector();
      String[] profilenames =  profiles.getProfileNames();
      String[] dummy = {};
      for(int i =0; i< profilenames.length; i++){
        if(profileauthproxy.getProfileAuthorization(profiles.getProfileId(profilenames[i]),ProfileAuthorizationProxy.EDIT_RIGHTS)){
          result.add(profilenames[i]);   
        }
      }
     
      return (String[]) result.toArray(dummy);
    }        
    
    public int getProfileId(String profilename) throws RemoteException{
      return profiles.getProfileId(profilename);   
    }

    /* Returns profiles as a Profiles object */
    public ProfileDataHandler getProfileDataHandler(){
      return profiles;
    }

    public Profile getProfile(String name) throws RemoteException{
      return profiles.getProfile(name);
    }
    
    public Profile getProfile(int id) throws RemoteException{
      return profiles.getProfile(id);
    }

    public String[][] getProfileAsString(String name) throws RemoteException{
      return profiles.getProfile(name).getAllValues();
    }
    
    public String[][] getProfileAsString(int id) throws RemoteException{
      return profiles.getProfile(id).getAllValues();
    }
    
    public void addProfile(String name) throws ProfileExistsException, RemoteException{
       profiles.addProfile(name, new Profile());
    }

    public void addProfile(String name, Profile profile) throws ProfileExistsException, RemoteException {
       profiles.addProfile(name, profile);
    }

    public void changeProfile(String name, Profile profile) throws ProfileDoesntExistsException, RemoteException {
       profiles.changeProfile(name, profile);
    }

    /* Returns false if profile is used by any user or in authorization rules. */
    public boolean removeProfile(String name)throws RemoteException{
        boolean profileused = false;
        int profileid = raadminsession.getProfileId(name);
        // Check if any users or authorization rule use the profile.

        profileused = adminsession.checkForProfileId(profileid) 
                      || authorizationsession.existsProfileInRules(profileid); 

        if(!profileused){
          profiles.removeProfile(name);
        }
        
        return !profileused;
    }

    public void renameProfile(String oldname, String newname) throws ProfileExistsException, RemoteException{
       profiles.renameProfile(oldname, newname);
    }

    public void cloneProfile(String originalname, String newname) throws ProfileExistsException, RemoteException{
      profiles.cloneProfile(originalname, newname);
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
    
    public boolean authorizedToEditUser(String profileid) throws RemoteException{
      return profileauthproxy.getProfileAuthorization(Integer.parseInt(profileid), ProfileAuthorizationProxy.EDIT_RIGHTS);
    }
    
    public boolean authorizedToViewHistory(String profileid) throws RemoteException{
      return profileauthproxy.getProfileAuthorization(Integer.parseInt(profileid), ProfileAuthorizationProxy.HISTORY_RIGHTS);
    }    
    
    public String[] getCertificateTypeNames() throws RemoteException{
      String[] dummy = {""};
      Collection certtypenames = certificatesession.getCertificateTypeNames();
      if(certtypenames == null)
        return new String[0];
      else        
        return (String[]) certtypenames.toArray(dummy); 
    }
    
    public int getCertificateTypeId(String certificatetypename) throws RemoteException{
      return certificatesession.getCertificateTypeId(certificatetypename); 
    }
    public String getCertificateTypeName(int certificatetypeid) throws RemoteException{
      return certtypenameproxy.getCertificateTypeName(certificatetypeid); 
    }
   
    // Private methods.

    // Private fields.

    private ProfileDataHandler             profiles;

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
    private ProfileAuthorizationProxy      profileauthproxy;
    private CertificateTypeNameProxy       certtypenameproxy;  
    private ProfileNameProxy               profilenameproxy;
    private GlobalConfiguration            globalconfiguration;
    private boolean initialized=false;
}
