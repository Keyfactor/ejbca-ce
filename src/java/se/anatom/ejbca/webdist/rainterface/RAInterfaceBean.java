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
import java.io.FileInputStream;
import java.rmi.RemoteException;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.math.BigInteger;

import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;
import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.CertificateDataPK;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.store.CertificateDataHome;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ra.UserData;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Hex;

/**
 * A java bean handling the interface between EJBCA ra module and JSP pages.
 * @author  Philip Vendil
 */
public class RAInterfaceBean extends Object implements java.io.Serializable {
    
    // Public constants.
    
    /** Creates new RaInterfaceBean */
    public RAInterfaceBean() throws FileNotFoundException, IOException, NamingException, CreateException  {
      users = new UsersView();  
      this.profiledatahandler = new ProfileDataHandler();
      profiles = this.profiledatahandler.loadProfilesData();
      
      // Get the UserSdminSession instance.
      Properties jndienv = new Properties();
      jndienv.load(new FileInputStream(GlobalConfiguration.getDocumentRoot() +"/WEB-INF/jndi.properties"));
      jndicontext = new InitialContext(jndienv);

      Object obj1 = jndicontext.lookup("UserAdminSession");
      adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
      adminsession = adminsessionhome.create(); 
      obj1 = jndicontext.lookup("CertificateStoreSession");
      certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
      certificatesession = certificatesessionhome.create();     

    }
    // Public methods.
    
    /* Adds a user to the database, the string array must be in format defined in class UserView. */
    public void addUser(String[] stringuserdata) throws RemoteException, FinderException{
        UserAdminData user = ( new UserView(stringuserdata)).convertToUserAdminData(); 
        adminsession.addUser(user.getUsername(), user.getPassword(), user.getDN(), user.getEmail(),user.getType());
        // if ra admin have chosen to store the password as cleartext.
        if(stringuserdata[UserView.CLEARTEXTPASSWORD] != null && stringuserdata[UserView.CLEARTEXTPASSWORD].equals(UserView.TRUE)){
          adminsession.setClearTextPassword(user.getUsername(), user.getPassword());            
        }
    }
    
    /* Removes a number of users from the database. */
    public void deleteUsers(String[] usernames) throws RemoteException{
       for(int i=0; i < usernames.length; i++){
         adminsession.deleteUser(usernames[i]);   
       }
    }
    
    public void setUserStatuses(String[] usernames, String status) throws RemoteException, FinderException{
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
        adminsession.setUserStatus(usernames[i], UserData.STATUS_REVOKED);
        

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
    public void changeUserData(String[] userdata) throws RemoteException, FinderException {
      adminsession.deleteUser(userdata[UserView.USERNAME]);
      addUser(userdata);
    }
    
    /* Method to filter out a user by it's username */
    public String[][] filterByUsername(String username) throws RemoteException, FinderException{
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
    public boolean userExist(String username) throws RemoteException, FinderException{
      return adminsession.findUser(username) != null;  
    }
    
    /* Method to retrieve a user from the database without inserting it into users data, used by 'viewuser.jsp' and 'edituser.jsp' pages*/ 
    public String[] findUser(String username) throws RemoteException, FinderException{
       UserAdminData user = adminsession.findUser(username);
       UserView UserView = new UserView(user);
       return UserView.getValues();
       
    }
    
    /* Method to filter out a user by it's status */
    public String[][] filterByStatus(String status, int index, int size) throws RemoteException, FinderException{
      Collection uservector = (Collection) adminsession.findAllUsersByStatus(Integer.parseInt(status));  
      
      users.setUsers(uservector);
      
      return users.getUsers(index,size);
    }
    
    /* Method that checks if a certificate serialnumber is revoked and returns the user(s), else a null value. */
    public String[][] filterByRevokedCertificates(String serialnumber, int index, int size) throws RemoteException, 
                                                                                                   FinderException, 
                                                                                                   NumberFormatException{                                                                                            
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
                                                                                            NumberFormatException{
      Vector uservector = new Vector();
      String[][] returnval = null;
      
      long d = Long.parseLong(days);
      Date finddate = new Date();
      long millis = (d * 24 * 60 * 60 * 1000);
      finddate.setTime(finddate.getTime() + (long)millis);
      
      Collection certs =certificatesession.findCertificatesByExpireTime(finddate); 
      if(!certs.isEmpty()){
        Iterator i = certs.iterator();  
        while(i.hasNext()){
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
    // Metods dealing with profiles.
    /** Returns all profile data as strings. The commonly used method in ra jsp pages.*/
    public String[][][] getProfilesAsString(){
      return profiles.getProfilesAsStrings();  
    }
    
    public String[] getProfileNames(){
      return profiles.getProfileNames();   
    }
    
    /* Returns profiles as a Profiles object */ 
    public Profiles getProfiles(){  
      return profiles;   
    }
    
    public Profile getProfile(String name){
      return profiles.getProfile(name);
    }
 
    public String[][] getProfileAsString(String name){  
      return profiles.getProfile(name).getAllValues();  
    }
    
    public void addProfile(String name) throws ProfileExistsException {
       profiles.addProfile(name, new Profile());  
       this.profiledatahandler.saveProfilesData(profiles);
    }    
    
    public void addProfile(String name, String[][] profilevalues) throws ProfileExistsException {
       profiles.addProfile(name, new Profile(profilevalues));  
       this.profiledatahandler.saveProfilesData(profiles);
    }
    
    public void removeProfile(String name){
        profiles.removeProfile(name);
        this.profiledatahandler.saveProfilesData(profiles);
    }
    
    public void renameProfile(String oldname, String newname) throws ProfileExistsException{
       profiles.renameProfile(oldname, newname);   
       this.profiledatahandler.saveProfilesData(profiles);
    }
    
    public void cloneProfile(String originalname, String newname) throws ProfileExistsException{
      profiles.cloneProfile(originalname, newname); 
      this.profiledatahandler.saveProfilesData(profiles);  
    }
    
    public void setDefaultProfile(String name){
      profiles.setDefaultProfile(name);
      this.profiledatahandler.saveProfilesData(profiles);        
    }
    
    public void saveProfileData(){
      this.profiledatahandler.saveProfilesData(profiles);         
    }
    
    public void reloadProfileData(){
      profiles = this.profiledatahandler.loadProfilesData();
    }
      
    public String getDefaultProfileName(){
      return profiles.getDefaultProfileName();   
    }
      
    public String[][] getDefaultProfileAsString(){
      return profiles.getDefaultProfileAsString();  
    }
    
    public void loadCertificates(String subjectdn) throws RemoteException{
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
    
    private Profiles                       profiles;
    private ProfileDataHandler             profiledatahandler;
    
    private InitialContext                 jndicontext; 
    private IUserAdminSession              adminsession;
    private IUserAdminSessionHome          adminsessionhome;
    private ICertificateStoreSessionRemote certificatesession; 
    private ICertificateStoreSessionHome   certificatesessionhome;
    
    private UsersView                      users;
    private CertificateView[]              certificates;
}
