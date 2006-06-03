/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.admin.rainterface;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.TreeMap;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocal;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.configuration.InformationMemory;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;
import org.ejbca.util.query.Query;



/**
 * A java bean handling the interface between EJBCA ra module and JSP pages.
 *
 * @author  Philip Vendil
 * @version $Id: RAInterfaceBean.java,v 1.4 2006-06-03 18:10:46 anatom Exp $
 */
public class RAInterfaceBean implements java.io.Serializable {
    
    private static Logger log = Logger.getLogger(RAInterfaceBean.class);
    
    // Public constants.
    public static final int MAXIMUM_QUERY_ROWCOUNT = SecConst.MAXIMUM_QUERY_ROWCOUNT;
    
    public static final String[] tokentexts = {"TOKENSOFTBROWSERGEN","TOKENSOFTP12","TOKENSOFTJKS","TOKENSOFTPEM"};
    public static final int[]    tokenids   = {SecConst.TOKEN_SOFT_BROWSERGEN,SecConst.TOKEN_SOFT_P12,SecConst.TOKEN_SOFT_JKS,SecConst.TOKEN_SOFT_PEM};
    
    /** Creates new RaInterfaceBean */
    public RAInterfaceBean()  {
        users = new UsersView();
        addedusermemory = new AddedUserMemory();
    }
    // Public methods.
    public void initialize(HttpServletRequest request, EjbcaWebBean ejbcawebbean) throws  Exception{
      log.debug(">initialize()");

      if(!initialized){
        if(request.getAttribute( "javax.servlet.request.X509Certificate" ) != null)
          administrator = new Admin(((X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" ))[0]);
        else
          administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());
        // Get the UserAdminSession instance.
        this.informationmemory = ejbcawebbean.getInformationMemory();
        
        ServiceLocator locator = ServiceLocator.getInstance();
        adminsessionhome = (IUserAdminSessionLocalHome) locator.getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
        adminsession = adminsessionhome.create();

        raadminsessionhome = (IRaAdminSessionLocalHome) locator.getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
        raadminsession = raadminsessionhome.create();
        

        certificatesessionhome = (ICertificateStoreSessionLocalHome) locator.getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
        certificatesession = certificatesessionhome.create();

        IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) locator.getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
        authorizationsession = authorizationsessionhome.create();

        this.profiles = new EndEntityProfileDataHandler(administrator,raadminsession,authorizationsession,informationmemory);
        
        IHardTokenSessionLocalHome hardtokensessionhome = (IHardTokenSessionLocalHome) locator.getLocalHome(IHardTokenSessionLocalHome.COMP_NAME);
        hardtokensession = hardtokensessionhome.create();

        IKeyRecoverySessionLocalHome keyrecoverysessionhome = (IKeyRecoverySessionLocalHome) locator.getLocalHome(IKeyRecoverySessionLocalHome.COMP_NAME);
        keyrecoverysession = keyrecoverysessionhome.create();
        
        

        initialized =true;
      } else {
          log.debug("=initialize(): already initialized");
      }
      log.debug("<initialize()");
    }
    
    /* Adds a user to the database, the string array must be in format defined in class UserView. */
    public void addUser(UserView userdata) throws Exception{
        log.debug(">addUser()");
        
        if(userdata.getEndEntityProfileId() != 0){
        	UserDataVO uservo = new UserDataVO(userdata.getUsername(), userdata.getSubjectDN(), userdata.getCAId(), userdata.getSubjectAltName(), 
        			userdata.getEmail(), UserDataConstants.STATUS_NEW, userdata.getType(), userdata.getEndEntityProfileId(), userdata.getCertificateProfileId(),
        			null,null, userdata.getTokenType(), userdata.getHardTokenIssuerId(), null);
        	uservo.setPassword(userdata.getPassword());
        	uservo.setExtendedinformation(userdata.getExtendedInformation());
        	adminsession.addUser(administrator, uservo, userdata.getClearTextPassword());
        	addedusermemory.addUser(userdata);
        } else {
            log.debug("=addUser(): profile id not set, user not created");
        }
        log.debug("<addUser()");
    }
    
    /* Removes a number of users from the database.
     *
     * @param usernames an array of usernames to delete.
     * @return false if administrator wasn't authorized to delete all of given users.
     * */
    public boolean deleteUsers(String[] usernames) throws Exception{
      log.debug(">deleteUsers()");
      boolean success = true;
      for(int i=0; i < usernames.length; i++){
         try{
           adminsession.deleteUser(administrator, usernames[i]);
         }catch(AuthorizationDeniedException e){
           success = false;
         }
      }
      log.debug("<deleteUsers(): " + success);
      return success;
    }

    /* Changes the status of a number of users from the database.
     *
     * @param usernames an array of usernames to change.
     * @param status gives the status to apply to users, should be one of UserDataRemote.STATUS constants.
     * @return false if administrator wasn't authorized to change all of the given users.
     * */
    public boolean setUserStatuses(String[] usernames, String status) throws Exception{
      log.debug(">setUserStatuses()");
      boolean success = true;
      int intstatus = 0;
      try{
        intstatus = Integer.parseInt(status);
      }catch(Exception e){}
      for(int i=0; i < usernames.length; i++){
        try{
          adminsession.setUserStatus(administrator, usernames[i],intstatus);
        }catch(AuthorizationDeniedException e){
           success = false;
        }
      }
      log.debug("<setUserStatuses(): " + success);
      return success;
    }

    /** Revokes the given users.
     *
     * @param users an array of usernames to revoke.
     * @param reason reason(s) of revokation.
     * @return false if administrator wasn't authorized to revoke all of the given users.
     */
    public boolean revokeUsers(String[] usernames, int reason) throws  Exception{
      log.debug(">revokeUsers()");
      boolean success = true;
      for(int i=0; i < usernames.length; i++){
        try{
          adminsession.revokeUser(administrator, usernames[i], reason);
        }catch( AuthorizationDeniedException e){
          success =false;
        }
      }
      log.debug("<revokeUsers(): " + success);
      return success;
    }

    /** Revokes the  certificate with certificate serno.
     *
     * @param serno serial number of certificate to revoke.
     * @param issuerdn the issuerdn of certificate to revoke.
     * @param reason reason(s) of revokation.
     * @return false if administrator wasn't authorized to revoke the given certificate.
     */
    public boolean revokeCert(BigInteger serno, String issuerdn, String username, int reason) throws  Exception{
      log.debug(">revokeCert()");
      boolean success = true;
      try{
        adminsession.revokeCert(administrator, serno, issuerdn, username, reason);
      }catch( AuthorizationDeniedException e){
        success =false;
      }
      log.debug("<revokeCert(): " + success);
      return success;
    }

    /* Changes the userdata  */
    public void changeUserData(UserView userdata) throws Exception {
        log.debug(">changeUserData()");

        addedusermemory.changeUser(userdata);
        if(userdata.getPassword() != null && userdata.getPassword().trim().equals(""))
          userdata.setPassword(null);
    	UserDataVO uservo = new UserDataVO(userdata.getUsername(), userdata.getSubjectDN(), userdata.getCAId(), userdata.getSubjectAltName(), 
    			userdata.getEmail(), UserDataConstants.STATUS_NEW, userdata.getType(), userdata.getEndEntityProfileId(), userdata.getCertificateProfileId(),
    			null,null, userdata.getTokenType(), userdata.getHardTokenIssuerId(), null);
    	uservo.setPassword(userdata.getPassword());
    	uservo.setExtendedinformation(userdata.getExtendedInformation());
    	adminsession.changeUser(administrator, uservo, userdata.getClearTextPassword());

        log.debug("<changeUserData()");
    }

    /* Method to filter out a user by it's username */
    public UserView[] filterByUsername(String username) throws Exception{
       log.debug(">filterByUserName()");
       UserDataVO[] userarray = new UserDataVO[1];
       UserDataVO user = null;
       try{
         user = adminsession.findUser(administrator, username);
       }catch(AuthorizationDeniedException e){
       }

       if(user != null){
         userarray[0]=user;
         users.setUsers(userarray, informationmemory.getCAIdToNameMap());
       }else{
         users.setUsers((UserDataVO[]) null, informationmemory.getCAIdToNameMap());
       }
       log.debug("<filterByUserName()");
       return users.getUsers(0,1);
    }

    /* Method used to check if user exists */
    public boolean userExist(String username) throws Exception{
       return adminsession.existsUser(administrator, username);
    }
    
    /* Method to retrieve a user from the database without inserting it into users data, used by 'viewuser.jsp' and page*/
    public UserView findUser(String username) throws Exception{
       log.debug(">findUser(" + username + ")");
       UserDataVO user = adminsession.findUser(administrator, username);
        UserView userview = null;
        if (user != null) {
            userview = new UserView(user, informationmemory.getCAIdToNameMap());
        }
        log.debug("<findUser(" + username + "): " + userview);
        return userview;
    }
    /* Method to retrieve a user from the database without inserting it into users data, used by 'edituser.jsp' and page*/
    public UserView findUserForEdit(String username) throws Exception{
       UserView userview = null;

       UserDataVO user = adminsession.findUser(administrator, username);
       
       if(this.informationmemory.getGlobalConfiguration().getEnableEndEntityProfileLimitations())
         if(!endEntityAuthorization(administrator, user.getEndEntityProfileId(),AvailableAccessRules.EDIT_RIGHTS, false))
           throw new AuthorizationDeniedException("Not authorized to edit user.");

       if(user != null)
        userview = new UserView(user, informationmemory.getCAIdToNameMap());
       return userview;
    }

    /* Method to find all users in database */
    public UserView[] findAllUsers(int index,int size) throws Exception{
       users.setUsers(adminsession.findAllUsersWithLimit(administrator), informationmemory.getCAIdToNameMap());
       return users.getUsers(index,size);

    }

    /* Method to find all users in database */
    public UserView[] filterByTokenSN(String tokensn, int index,int size) throws Exception{
      UserView[] returnval = null;
      UserDataVO user = null;
      ArrayList userlist = new ArrayList();
      
      Collection usernames = hardtokensession.findHardTokenByTokenSerialNumber(administrator, tokensn);
     
      Iterator iter = usernames.iterator();
      while(iter.hasNext()){       	 
         try{  
           user = adminsession.findUser(administrator, (String) iter.next());
         }catch(AuthorizationDeniedException e){}
        
         if(user!=null)
           userlist.add(user);
      }
     
      users.setUsers(userlist, informationmemory.getCAIdToNameMap());

      returnval= users.getUsers(index,size);

      return returnval;
    }

    /* Method that checks if a certificate serialnumber is revoked and returns the user(s), else a null value. */
    public UserView[] filterByCertificateSerialNumber(String serialnumber, int index, int size) throws RemoteException,
                                                                                                   FinderException,
                                                                                                   NamingException,
                                                                                                   NumberFormatException,
                                                                                                   CreateException{
      serialnumber = StringTools.stripWhitespace(serialnumber);
      Collection certs =certificatesession.findCertificatesBySerno(administrator, new BigInteger(serialnumber,16));
      ArrayList userlist = new ArrayList();
      UserView[] returnval = null;
      if(certs != null){
        Iterator iter = certs.iterator();
        while(iter.hasNext()){
           UserDataVO user = null;
           try{
             X509Certificate next = (X509Certificate) iter.next();  
             user = adminsession.findUserBySubjectDN(administrator, CertTools.getSubjectDN(next), next.getIssuerDN().toString());
             userlist.add(user);
           }catch(AuthorizationDeniedException e){}
        }
        users.setUsers(userlist, informationmemory.getCAIdToNameMap());

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
      ArrayList userlist = new ArrayList();
      UserView[] returnval = null;

      long d = Long.parseLong(days);
      Date finddate = new Date();
      long millis = (d * 86400000); // One day in milliseconds.
      finddate.setTime(finddate.getTime() + millis);

      Collection usernames =certificatesession.findCertificatesByExpireTimeWithLimit(administrator, finddate);
      if(!usernames.isEmpty()){
        Iterator i = usernames.iterator();
        while(i.hasNext() && userlist.size() <= MAXIMUM_QUERY_ROWCOUNT +1 ){
           UserDataVO user = null;
           try{
             user = adminsession.findUser(administrator, (String) i.next());
             if(user != null)
               userlist.add(user);
           }catch(AuthorizationDeniedException e){}
        }
        users.setUsers(userlist, informationmemory.getCAIdToNameMap());

        returnval= users.getUsers(index,size);
      }
      return returnval;
    }

    public UserView[] filterByQuery(Query query, int index, int size) throws Exception {
      Collection userlist = adminsession.query(administrator, query, informationmemory.getUserDataQueryCAAuthoorizationString(), informationmemory.getUserDataQueryEndEntityProfileAuthorizationString(),0);
      users.setUsers(userlist, informationmemory.getCAIdToNameMap());

      return users.getUsers(index,size);
    }

    public int getResultSize(){
     return users.size();
    }

    public boolean isAuthorizedToViewUserHistory(String username) throws Exception {
      UserDataVO user = adminsession.findUser(administrator, username);
      return endEntityAuthorization(administrator, user.getEndEntityProfileId(),AvailableAccessRules.HISTORY_RIGHTS, false);
    }
    
    public boolean isAuthorizedToEditUser(String username) throws Exception {
        UserDataVO user = adminsession.findUser(administrator, username);
        return endEntityAuthorization(administrator, user.getEndEntityProfileId(),AvailableAccessRules.EDIT_RIGHTS, false);
      }

    /* Method to resort filtered user data. */
    public void sortUserData(int sortby, int sortorder){
      users.sortBy(sortby,sortorder);
    }

    /* Method to return the users between index and size, if userdata is smaller than size, a smaller array is returned. */
    public UserView[] getUsers(int index, int size){
      return users.getUsers(index, size);
    }

    /* Method that clears the userview memory. */
    public void clearUsers(){
      users.clear();
    }

    public boolean nextButton(int index, int size){
      return index + size < users.size();
    }
    public boolean previousButton(int index){
      return index > 0 ;
    }

    // Method dealing with added user memory.
    /** A method to get the last added users in adduser.jsp.
     *
     * @see org.ejbca.ui.web.admin.rainterface.AddedUserMemory
     */
    public UserView[] getAddedUsers(int size){
      return addedusermemory.getUsers(size);
    }

    // Methods dealing with profiles.


    public TreeMap getAuthorizedEndEntityProfileNames() {
      return informationmemory.getAuthorizedEndEntityProfileNames();
    }

    /** Returns the profile name from id proxied */
    public String getEndEntityProfileName(int profileid) throws RemoteException{
      return this.informationmemory.getEndEntityProfileNameProxy().getEndEntityProfileName(profileid);
    }

    public int getEndEntityProfileId(String profilename){
      return profiles.getEndEntityProfileId(profilename);
    }


    public EndEntityProfile getEndEntityProfile(String name)  throws Exception{
      return profiles.getEndEntityProfile(name);
    }

    public EndEntityProfile getEndEntityProfile(int id)  throws Exception{
      return profiles.getEndEntityProfile(id);
    }

    public void addEndEntityProfile(String name) throws Exception{
       EndEntityProfile profile = new EndEntityProfile();
       Iterator iter = this.informationmemory.getAuthorizedCAIds().iterator();
       String availablecas = "";
       if(iter.hasNext())
         availablecas = ((Integer) iter.next()).toString();  
       
       while(iter.hasNext()){
         availablecas = availablecas + EndEntityProfile.SPLITCHAR + ((Integer) iter.next()).toString();     
       }
       
       profile.setValue(EndEntityProfile.AVAILCAS, 0,availablecas);
       profile.setRequired(EndEntityProfile.AVAILCAS, 0,true); 
        
       profiles.addEndEntityProfile(name, profile);
    }

   
    public void changeEndEntityProfile(String name, EndEntityProfile profile) throws Exception {
       profiles.changeEndEntityProfile(name, profile);
    }

    /* Returns false if profile is used by any user or in authorization rules. */
    public boolean removeEndEntityProfile(String name)throws Exception{
        boolean profileused = false;
        int profileid = raadminsession.getEndEntityProfileId(administrator, name);
        // Check if any users or authorization rule use the profile.

        profileused = adminsession.checkForEndEntityProfileId(administrator, profileid)
                      || authorizationsession.existsEndEntityProfileInRules(administrator, profileid);

        if(!profileused){
          profiles.removeEndEntityProfile(name);
        }

        return !profileused;
    }

    public void renameEndEntityProfile(String oldname, String newname) throws Exception{
       profiles.renameEndEntityProfile(oldname, newname);
    }

    public void cloneEndEntityProfile(String originalname, String newname) throws Exception{
      profiles.cloneEndEntityProfile(originalname, newname);
    }

    public void loadCertificates(String username) throws Exception{
        Collection certs = certificatesession.findCertificatesByUsername(administrator, username);    
        loadCertificateView(certs, username);
    }

    public void loadTokenCertificates(String tokensn, String username) throws RemoteException, NamingException, CreateException, AuthorizationDeniedException, FinderException{
        Collection certs = hardtokensession.findCertificatesInHardToken(administrator, tokensn);
        loadCertificateView(certs, username);
    }
    
    /** Helper method loading CertificateView and RevokedInfoView arrays given a collection of certificates.
     * 
     * @param certs certificates to process
     * @param username user the certs belong to
     */
    private void loadCertificateView(Collection certs, String username) {
    	if(!certs.isEmpty()){
    		Iterator j = certs.iterator();
    		certificates = new CertificateView[certs.size()];
    		for(int i=0; i< certificates.length; i++){
    			RevokedInfoView revokedinfo = null;
    			X509Certificate cert = (X509Certificate) j.next();
    			RevokedCertInfo revinfo = certificatesession.isRevoked(administrator, CertTools.getIssuerDN(cert), cert.getSerialNumber());
    			if(revinfo != null) {
    				revokedinfo = new RevokedInfoView(revinfo);
    			}
    			certificates[i] = new CertificateView(cert, revokedinfo, username);
    		}
    	}
    	else{
    		certificates = null;
    	}
    } // loadCertificateView

    public boolean revokeTokenCertificates(String tokensn, String username, int reason) throws RemoteException, NamingException, CreateException, AuthorizationDeniedException, FinderException{
       boolean success = true;

       Collection certs = hardtokensession.findCertificatesInHardToken(administrator, tokensn);
       Iterator i = certs.iterator();
       try{
         while(i.hasNext()){
           X509Certificate cert = (X509Certificate) i.next();  
           adminsession.revokeCert(administrator, cert.getSerialNumber(), cert.getIssuerDN().toString(), username, reason);
         }
       }catch( AuthorizationDeniedException e){
         success =false;
       }

       return success;
    }

    public boolean isAllTokenCertificatesRevoked(String tokensn, String username) throws RemoteException, NamingException, CreateException, AuthorizationDeniedException, FinderException{
      Collection certs = hardtokensession.findCertificatesInHardToken(administrator, tokensn);

      boolean allrevoked = true;

      if(!certs.isEmpty()){
        Iterator j = certs.iterator();
        while(j.hasNext()){
          X509Certificate cert = (X509Certificate) j.next();        
          RevokedCertInfo revinfo = certificatesession.isRevoked(administrator, CertTools.getIssuerDN(cert), cert.getSerialNumber());          
          if(revinfo == null || revinfo.getReason()== RevokedCertInfo.NOT_REVOKED)
            allrevoked = false;
        }
      }

      return allrevoked;
    }
    


    public void loadCACertificates(CertificateView[] cacerts) {
        certificates = cacerts;
    }

    public void loadCertificates(BigInteger serno, String issuerdn) throws RemoteException, NamingException, CreateException, AuthorizationDeniedException, FinderException{
	  try{	
		  authorizationsession.isAuthorizedNoLog(administrator, AvailableAccessRules.CAPREFIX + issuerdn.hashCode());        
		  X509Certificate cert = (X509Certificate) certificatesession.findCertificateByIssuerAndSerno(administrator, issuerdn, serno);
		  
		  if(cert != null){
			  RevokedInfoView revokedinfo = null;
			  String username = certificatesession.findUsernameByCertSerno(administrator,serno, cert.getIssuerDN().toString());
			  if(this.adminsession.findUser(administrator, username) != null){
				  int endentityprofileid = this.adminsession.findUser(administrator, username).getEndEntityProfileId();
				  this.endEntityAuthorization(administrator,endentityprofileid,AvailableAccessRules.VIEW_RIGHTS,true);
			  }
			  RevokedCertInfo revinfo = certificatesession.isRevoked(administrator, CertTools.getIssuerDN(cert), cert.getSerialNumber());
			  if(revinfo != null)
				  revokedinfo = new RevokedInfoView(revinfo);
			  
			  certificates = new CertificateView[1];
			  certificates[0] = new CertificateView(cert, revokedinfo, username);
			  
		  }
		  else{
			  certificates = null;
		  }
	  }catch(AuthorizationDeniedException ade){
		  throw new AuthorizationDeniedException("Not authorized to view certificate, error: " + ade.getMessage());
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
      return endEntityAuthorization(administrator, profileid, AvailableAccessRules.EDIT_RIGHTS, false);
    }

    public boolean authorizedToViewHistory(int profileid) throws RemoteException{
      return endEntityAuthorization(administrator, profileid, AvailableAccessRules.HISTORY_RIGHTS, false);
    }

    public boolean authorizedToViewHardToken(String username) throws Exception{
      int profileid = adminsession.findUser(administrator, username).getEndEntityProfileId();
      return endEntityAuthorization(administrator, profileid, AvailableAccessRules.HARDTOKEN_RIGHTS, false);
    }

    public boolean authorizedToViewHardToken(int profileid) throws Exception{
      return endEntityAuthorization(administrator, profileid, AvailableAccessRules.HARDTOKEN_RIGHTS, false);
    }

    public boolean authorizedToRevokeCert(String username) throws FinderException, RemoteException, AuthorizationDeniedException{
      boolean returnval=false;
      UserDataVO data = adminsession.findUser(administrator, username);
      if(data == null)
        return false;
              
      int profileid = data.getEndEntityProfileId();

      if(informationmemory.getGlobalConfiguration().getEnableEndEntityProfileLimitations())
       returnval= endEntityAuthorization(administrator, profileid, AvailableAccessRules.REVOKE_RIGHTS, false);
      else
       returnval=true;

      return returnval;
    }


    public boolean keyRecoveryPossible(X509Certificate cert, String username) throws Exception{
      boolean returnval = true;
      
      try{
        authorizationsession.isAuthorizedNoLog(administrator, AvailableAccessRules.REGULAR_KEYRECOVERY);
      }catch(AuthorizationDeniedException ade){
      	returnval = false;
      }
	  
      if(informationmemory.getGlobalConfiguration().getEnableEndEntityProfileLimitations()){
      	UserDataVO data = adminsession.findUser(administrator, username);
      	if(data != null){       	
          int profileid = data.getEndEntityProfileId();
		  returnval = endEntityAuthorization(administrator, profileid, AvailableAccessRules.KEYRECOVERY_RIGHTS, false);		  
      	}else
          returnval = false;         
      }

      return returnval && keyrecoverysession.existsKeys(administrator, cert) && !keyrecoverysession.isUserMarked(administrator,username);
    }

    public void markForRecovery(String username, X509Certificate cert) throws Exception{
      boolean authorized = true;
      if(informationmemory.getGlobalConfiguration().getEnableEndEntityProfileLimitations()){
        int profileid = adminsession.findUser(administrator, username).getEndEntityProfileId();
        authorized = endEntityAuthorization(administrator, profileid, AvailableAccessRules.KEYRECOVERY_RIGHTS, false);
      }

      if(authorized){
        keyrecoverysession.markAsRecoverable(administrator, cert);
        adminsession.setUserStatus(administrator, username,UserDataConstants.STATUS_KEYRECOVERY);
      }
    }

    public String[] getCertificateProfileNames(){
        String[] dummy = {""};
        Collection certprofilenames = this.informationmemory.getAuthorizedEndEntityCertificateProfileNames().keySet();
        if(certprofilenames == null)
            return new String[0];
        return (String[]) certprofilenames.toArray(dummy);
    }

    public int getCertificateProfileId(String certificateprofilename) throws RemoteException{
      return certificatesession.getCertificateProfileId(administrator, certificateprofilename);
    }
    public String getCertificateProfileName(int certificateprofileid) throws RemoteException{
      return this.informationmemory.getCertificateProfileNameProxy().getCertificateProfileName(certificateprofileid);
    }

    public boolean getEndEntityParameter(String parameter){
       if(parameter == null)
         return false;

       return parameter.equals(EndEntityProfile.TRUE);
    }

    /**
     * Help function used to check end entity profile authorization.
     */
    public boolean endEntityAuthorization(Admin admin, int profileid, String rights, boolean log) throws RemoteException {
      boolean returnval = false;
      
      // TODO FIX
      if(admin.getAdminInformation().isSpecialUser()){
        return true;
      }
      try{
        if(log)
           returnval = authorizationsession.isAuthorized(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX+Integer.toString(profileid)+rights) &&
           authorizationsession.isAuthorized(admin, AvailableAccessRules.REGULAR_RAFUNCTIONALITY + rights);
        else
           returnval = authorizationsession.isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX+Integer.toString(profileid)+rights)&&
           authorizationsession.isAuthorized(admin, AvailableAccessRules.REGULAR_RAFUNCTIONALITY + rights);
      }catch(AuthorizationDeniedException e){}

      return returnval;
    }    

    /**
     *  Help functiosn used by edit end entity pages used to temporary save a profile 
     *  so things can be canceled later
     */
    public EndEntityProfile getTemporaryEndEntityProfile(){
    	return this.temporateendentityprofile;
    }
    
    public void setTemporaryEndEntityProfile(EndEntityProfile profile){
    	this.temporateendentityprofile = profile;
    }

    //
    // Private fields.
    //
    private EndEntityProfileDataHandler    profiles;

    private IUserAdminSessionLocal                 adminsession;
    private IUserAdminSessionLocalHome        adminsessionhome;
    private ICertificateStoreSessionLocal          certificatesession;
    private ICertificateStoreSessionLocalHome certificatesessionhome;
    private IRaAdminSessionLocalHome            raadminsessionhome;
    private IRaAdminSessionLocal                     raadminsession;
    private IAuthorizationSessionLocal              authorizationsession;
    private IHardTokenSessionLocal                  hardtokensession;
    private IKeyRecoverySessionLocal               keyrecoverysession;

    private UsersView                           users;
    private CertificateView[]                  certificates;
    private AddedUserMemory              addedusermemory;
    private Admin                                 administrator;   
    private InformationMemory             informationmemory;
    private boolean initialized=false;
    
    private EndEntityProfile temporateendentityprofile = null;  
}
