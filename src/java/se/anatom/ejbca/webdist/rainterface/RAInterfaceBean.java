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
import java.io.Serializable;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.math.BigInteger;

import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
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
import se.anatom.ejbca.util.query.*;

/**
 * A java bean handling the interface between EJBCA ra module and JSP pages.
 *
 * @author  Philip Vendil
 * @version $Id: RAInterfaceBean.java,v 1.10 2002-07-28 23:27:47 herrvendil Exp $
 */
public class RAInterfaceBean {

    // Public constants.
    public static final int MAXIMUM_QUERY_ROWCOUNT = IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT;

    /** Creates new RaInterfaceBean */
    public RAInterfaceBean() throws  IOException, NamingException, FinderException, CreateException  {  
      users = new UsersView();
      addedusermemory = new AddedUserMemory();
      
      this.profiles = new ProfileDataHandler();

      // Get the UserAdminSession instance.
      jndicontext = new InitialContext();
      Object obj1 = jndicontext.lookup("UserAdminSession");
      adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
      adminsession = adminsessionhome.create();
 
      obj1 = jndicontext.lookup("CertificateStoreSession");
      certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
      certificatesession = certificatesessionhome.create();
      
      obj1 = jndicontext.lookup("RaAdminSession");
      raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"), 
                                                                                 IRaAdminSessionHome.class);
      raadminsession = raadminsessionhome.create();           
    
    }
    // Public methods.

    /* Adds a user to the database, the string array must be in format defined in class UserView. */
    public void addUser(String[] stringuserdata) throws RemoteException, NamingException, FinderException, CreateException{
        // lookup profileid and certificatetype id;
        if(stringuserdata[UserView.PROFILE] != null){
          if(stringuserdata[UserView.PROFILE].trim() != ""){
            int profileid =  raadminsession.getProfileId(stringuserdata[UserView.PROFILE].trim());
            int certificatetypeid = UserAdminData.NO_CERTIFICATETYPE; // TEMPORARY
            if(profileid != 0){
              UserView userview =  new UserView(stringuserdata,null,null,profileid,certificatetypeid );
              addedusermemory.addUser(userview);
              UserAdminData user = userview.convertToUserAdminData();
              adminsession.addUser(user.getUsername(), user.getPassword(), user.getDN(), user.getEmail()
                                   ,user.getType(),profileid, certificatetypeid);
               // if ra admin have chosen to store the password as cleartext.
               if(stringuserdata[UserView.CLEARTEXTPASSWORD] != null && stringuserdata[UserView.CLEARTEXTPASSWORD].equals(UserView.TRUE)){
                 adminsession.setClearTextPassword(user.getUsername(), user.getPassword());
               }
            }
          }
        }  
    }

    /* Removes a number of users from the database. */
    public void deleteUsers(String[] usernames) throws RemoteException, NamingException, CreateException{

      for(int i=0; i < usernames.length; i++){
         adminsession.deleteUser(usernames[i]);
      }
    }

    public void setUserStatuses(String[] usernames, String status) throws RemoteException, NamingException, FinderException, CreateException{
      int intstatus = 0;
      try{
        intstatus = Integer.parseInt(status);
      }catch(Exception e){}
      for(int i=0; i < usernames.length; i++){
        adminsession.setUserStatus(usernames[i],intstatus);
      }
    }

    public void revokeUsers(String[] usernames) throws  Exception{

      for(int i=0; i < usernames.length; i++){
        UserAdminData data = adminsession.findUser(usernames[i]);
        adminsession.setUserStatus(usernames[i], UserDataRemote.STATUS_REVOKED);


        Collection certs = certificatesession.findCertificatesBySubject(data.getDN());
        // Revoke all certs
        if (!certs.isEmpty()) {
          Iterator j = certs.iterator();
          Object obj = jndicontext.lookup("CertificateData");
          CertificateDataHome home = (CertificateDataHome) javax.rmi.PortableRemoteObject.narrow(obj, CertificateDataHome.class);
          while (j.hasNext()) {
            CertificateDataPK revpk = new CertificateDataPK();
            revpk.fingerprint = CertTools.getFingerprintAsString((X509Certificate) j.next());
            CertificateData rev = home.findByPrimaryKey(revpk);
            if (rev.getStatus() != CertificateData.CERT_REVOKED) {
              rev.setStatus(CertificateData.CERT_REVOKED);
              rev.setRevocationDate(new Date());
            }
          }
        }
      }
    }

    /* Changes the userdata  */
    public void changeUserData(String[] userdata) throws RemoteException, NamingException, FinderException, CreateException {
        int profileid = UserAdminData.NO_PROFILE;
        int certificatetypeid = UserAdminData.NO_CERTIFICATETYPE; // TEMPORARY        
        // lookup profileid and certificatetype id;
        if(userdata[UserView.PROFILE] != null){
          if(userdata[UserView.PROFILE].trim() != ""){
            profileid =  raadminsession.getProfileId(userdata[UserView.PROFILE].trim());
          }
        }
        
        UserView userview = new UserView(userdata,null,null,profileid,certificatetypeid);
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
       UserAdminData user = adminsession.findUser(username);

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
      return adminsession.findUser(username) != null;
    }

    /* Method to retrieve a user from the database without inserting it into users data, used by 'viewuser.jsp' and 'edituser.jsp' pages*/
    public UserView findUser(String username) throws RemoteException, NamingException, FinderException, CreateException{

       UserAdminData user = adminsession.findUser(username);
       UserView userview = new UserView(user,raadminsession.getProfileName(user.getProfileId()), "NO_CERTIFICATE_TYPE"); // TEMPORATE
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
           UserAdminData user = adminsession.findUserBySubjectDN(((X509Certificate) iter.next()).getSubjectDN().toString());
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
      String[][] returnval = null;

      long d = Long.parseLong(days);
      Date finddate = new Date();
      long millis = (d * 24 * 60 * 60 * 1000);
      finddate.setTime(finddate.getTime() + (long)millis);

      Collection certs =certificatesession.findCertificatesByExpireTime(finddate);
      if(!certs.isEmpty()){
        Iterator i = certs.iterator();
        while(i.hasNext() && uservector.size() <= MAXIMUM_QUERY_ROWCOUNT ){
           UserAdminData user = adminsession.findUserBySubjectDN(((X509Certificate) i.next()).getSubjectDN().toString());
           if(user != null){
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

    public String[][] getProfileAsString(String name) throws RemoteException{
      return profiles.getProfile(name).getAllValues();
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

    public void removeProfile(String name)throws RemoteException{
        profiles.removeProfile(name);
    }

    public void renameProfile(String oldname, String newname) throws ProfileExistsException, RemoteException{
       profiles.renameProfile(oldname, newname);
    }

    public void cloneProfile(String originalname, String newname) throws ProfileExistsException, RemoteException{
      profiles.cloneProfile(originalname, newname);
    }

    public String[][] getLastProfileAsString(String lastprofilename) throws RemoteException{
      return profiles.getLastProfileAsString(lastprofilename);
    }

    public Profile getLastProfile(String lastprofilename) throws RemoteException{
      return profiles.getLastProfile(lastprofilename);
    }

    public void loadCertificates(String subjectdn) throws RemoteException, NamingException, CreateException{
      if(certificatesession == null){
        Object obj1 = jndicontext.lookup("CertificateStoreSession");
        certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
        certificatesession = certificatesessionhome.create();
      }
      Collection certs = certificatesession.findCertificatesBySubject(subjectdn);

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

    private UsersView                      users;
    private CertificateView[]              certificates;
    private AddedUserMemory                addedusermemory;
}
