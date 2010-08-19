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
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.TreeMap;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import javax.ejb.RemoveException;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSession;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSession;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserAdminConstants;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.CertificateView;
import org.ejbca.ui.web.RevokedInfoView;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.configuration.InformationMemory;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;
import org.ejbca.util.cert.CertificateNotBeforeComparator;
import org.ejbca.util.query.Query;

/**
 * A java bean handling the interface between EJBCA ra module and JSP pages.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class RAInterfaceBean implements java.io.Serializable {
    
    private static Logger log = Logger.getLogger(RAInterfaceBean.class);
    
    // Public constants.
    public static final int MAXIMUM_QUERY_ROWCOUNT = UserAdminConstants.MAXIMUM_QUERY_ROWCOUNT;
    
    public static final String[] tokentexts = SecConst.TOKENTEXTS;
    public static final int[]    tokenids   = SecConst.TOKENIDS;
    
    private EjbLocalHelper ejb = new EjbLocalHelper();
    
    /** Creates new RaInterfaceBean */
    public RAInterfaceBean()  {
        users = new UsersView();
        addedusermemory = new AddedUserMemory();
    }
    // Public methods.
    public void initialize(HttpServletRequest request, EjbcaWebBean ejbcawebbean) throws  Exception{
      log.trace(">initialize()");
      if(!initialized){
        if(request.getAttribute( "javax.servlet.request.X509Certificate" ) != null) {
          administrator = ejbcawebbean.getAdminObject();
        }
        else { 
          administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());
        }
        // Get the UserAdminSession instance.
        this.informationmemory = ejbcawebbean.getInformationMemory();
        
        ServiceLocator locator = ServiceLocator.getInstance();
        adminsession = ejb.getUserAdminSession();
        raadminsession = ejb.getRAAdminSession();
        certificatesession = ejb.getCertStoreSession();
        CAAdminSession caadminsession = ejb.getCAAdminSession();
        authorizationsession = ejb.getAuthorizationSession();

        this.profiles = new EndEntityProfileDataHandler(administrator,raadminsession,authorizationsession,caadminsession,informationmemory);
        
        hardtokensession = ejb.getHardTokenSession();
        keyrecoverysession = ejb.getKeyRecoverySession();
        userdatasourcesession = ejb.getUserDataSourceSession();        

        initialized =true;
      } else {
          log.debug("=initialize(): already initialized");
      }
      log.trace("<initialize()");
    }
    
    /* Adds a user to the database, the string array must be in format defined in class UserView. */
    public void addUser(UserView userdata) throws Exception {
        log.trace(">addUser()");
        if(userdata.getEndEntityProfileId() != 0){
            UserDataVO uservo = new UserDataVO(userdata.getUsername(), userdata.getSubjectDN(), userdata.getCAId(), userdata.getSubjectAltName(), 
        		userdata.getEmail(), UserDataConstants.STATUS_NEW, userdata.getType(), userdata.getEndEntityProfileId(), userdata.getCertificateProfileId(),
        		null,null, userdata.getTokenType(), userdata.getHardTokenIssuerId(), null);
            uservo.setPassword(userdata.getPassword());
            uservo.setExtendedinformation(userdata.getExtendedInformation());
            uservo.setCardNumber(userdata.getCardNumber());
            adminsession.addUser(administrator, uservo, userdata.getClearTextPassword());
            addedusermemory.addUser(userdata);

        } else {
            log.debug("=addUser(): profile id not set, user not created");
        }
        log.trace("<addUser()");
    }
    
    /* Removes a number of users from the database.
     *
     * @param usernames an array of usernames to delete.
     * @return false if administrator wasn't authorized to delete all of given users.
     * */
    public boolean deleteUsers(String[] usernames) throws Exception{
      log.trace(">deleteUsers()");
      boolean success = true;
      for(int i=0; i < usernames.length; i++){
         try{
           adminsession.deleteUser(administrator, usernames[i]);
         }catch(AuthorizationDeniedException e){
           success = false;
         }
      }
      log.trace("<deleteUsers(): " + success);
      return success;
    }

    /* Changes the status of a number of users from the database.
     *
     * @param usernames an array of usernames to change.
     * @param status gives the status to apply to users, should be one of UserDataRemote.STATUS constants.
     * @return false if administrator wasn't authorized to change all of the given users.
     * */
    public boolean setUserStatuses(String[] usernames, String status) throws Exception{
      log.trace(">setUserStatuses()");
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
      log.trace("<setUserStatuses(): " + success);
      return success;
    }

    /**
     * Revokes the given user.
     * @param users an array of usernames to revoke.
     * @param reason reason(s) of revokation.
     * @return false if administrator wasn't authorized to revoke all of the given users.
     */
    public void revokeUser(String username, int reason) throws AuthorizationDeniedException,
    		FinderException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException {
        log.trace(">revokeUser()");
        adminsession.revokeUser(administrator, username, reason);
        log.trace("<revokeUser()");
    }

    public void revokeAndDeleteUser(String username, int reason) throws AuthorizationDeniedException,
    		ApprovalException, WaitingForApprovalException, RemoveException, NotFoundException {
		log.trace(">revokeUser()");
		adminsession.revokeAndDeleteUser(administrator, username, reason);
		log.trace("<revokeUser()");
    }
    
    /** Revokes the  certificate with certificate serno.
     *
     * @param serno serial number of certificate to revoke.
     * @param issuerdn the issuerdn of certificate to revoke.
     * @param reason reason(s) of revokation.
     * @return false if administrator wasn't authorized to revoke the given certificate.
     */
    public boolean revokeCert(BigInteger serno, String issuerdn, String username, int reason) throws ApprovalException, WaitingForApprovalException {
    	if (log.isTraceEnabled()) {
        	log.trace(">revokeCert(): "+username+", "+reason);    		
    	}
    	boolean success = true;
    	try {
    		adminsession.revokeCert(administrator, serno, issuerdn, username, reason);
    	} catch( AuthorizationDeniedException e) {
    		success = false;
    	} catch (FinderException e) {
    		success = false;
    	} catch (AlreadyRevokedException e) {
    		success = false;
		}
    	if (log.isTraceEnabled()) {
    		log.trace("<revokeCert(): " + success);
    	}
    	return success;
    }

    /** 
     * Reactivates the certificate with certificate serno.
     *
     * @param serno serial number of certificate to reactivate.
     * @param issuerdn the issuerdn of certificate to reactivate.
     * @param username the username joined to the certificate.
     * @return false if administrator wasn't authorized to unrevoke the given certificate.
     */
    public boolean unrevokeCert(BigInteger serno, String issuerdn, String username) throws ApprovalException, WaitingForApprovalException {
    	// Method needed because it is used as an ApprovalOveradableClassName
    	return revokeCert(serno, issuerdn, username, RevokedCertInfo.NOT_REVOKED);
    }
    
    /* Changes the userdata  */
    public void changeUserData(UserView userdata) throws Exception {
        log.trace(">changeUserData()");

        addedusermemory.changeUser(userdata);
        if(userdata.getPassword() != null && userdata.getPassword().trim().equals("")) {
          userdata.setPassword(null);
        }
    	UserDataVO uservo = new UserDataVO(userdata.getUsername(), userdata.getSubjectDN(), userdata.getCAId(), userdata.getSubjectAltName(), 
    			userdata.getEmail(), userdata.getStatus(), userdata.getType(), userdata.getEndEntityProfileId(), userdata.getCertificateProfileId(),
    			null,null, userdata.getTokenType(), userdata.getHardTokenIssuerId(), null);
    	uservo.setPassword(userdata.getPassword());
    	uservo.setExtendedinformation(userdata.getExtendedInformation());
    	uservo.setCardNumber(userdata.getCardNumber());
    	adminsession.changeUser(administrator, uservo, userdata.getClearTextPassword());

        log.trace("<changeUserData()");
    }

    /* Method to filter out a user by it's username */
    public UserView[] filterByUsername(String username) throws Exception{
       log.trace(">filterByUserName()");
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
       log.trace("<filterByUserName()");
       return users.getUsers(0,1);
    }

    /* Method used to check if user exists */
    public boolean userExist(String username) throws Exception{
       return adminsession.existsUser(administrator, username);
    }
        
    /* Method to retrieve a user from the database without inserting it into users data, used by 'viewuser.jsp' and page*/
    public UserView findUser(String username) throws Exception{
    	if (log.isTraceEnabled()) {
    		log.trace(">findUser(" + username + ")");
    	}
    	UserDataVO user = adminsession.findUser(administrator, username);
    	UserView userview = null;
    	if (user != null) {
    		userview = new UserView(user, informationmemory.getCAIdToNameMap());
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<findUser(" + username + "): " + userview);
    	}
    	return userview;
    }
    /* Method to retrieve a user from the database without inserting it into users data, used by 'edituser.jsp' and page*/
    public UserView findUserForEdit(String username) throws Exception{
       UserView userview = null;

       UserDataVO user = adminsession.findUser(administrator, username);
       
       if(this.informationmemory.getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
         if(!endEntityAuthorization(administrator, user.getEndEntityProfileId(),AccessRulesConstants.EDIT_RIGHTS, false)) {
           throw new AuthorizationDeniedException("Not authorized to edit user.");
         }
       }
       if(user != null) {
        userview = new UserView(user, informationmemory.getCAIdToNameMap());
       }
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
      
      Collection usernames = hardtokensession.matchdHardTokenByTokenSerialNumber(administrator, tokensn);
     
      Iterator iter = usernames.iterator();
      while(iter.hasNext()){
         try{  
           user = adminsession.findUser(administrator, (String) iter.next());
         }catch(AuthorizationDeniedException e){}
        
         if(user!=null) {
           userlist.add(user);
         }
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
      BigInteger serno = new BigInteger(serialnumber,16);
      Collection certs =certificatesession.findCertificatesBySerno(administrator, serno);
      ArrayList userlist = new ArrayList();
      UserView[] returnval = null;
      if(certs != null){
        Iterator iter = certs.iterator();
        UserDataVO user = null;
        while(iter.hasNext()){
           try{
             Certificate next = (Certificate) iter.next();  
             user = adminsession.findUserBySubjectAndIssuerDN(administrator, CertTools.getSubjectDN(next), CertTools.getIssuerDN(next));
             if(user != null){
            	 userlist.add(user);
             }
             String username = certificatesession.findUsernameByCertSerno(administrator, serno, CertTools.getIssuerDN(next));
             if ( (user == null) || (!StringUtils.equals(username, user.getUsername())) ) {
            	 user = adminsession.findUser(administrator, username);
                 if(user != null){
                	 userlist.add(user);
                 }            	 
             }
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
        while(i.hasNext() && userlist.size() <= UserAdminConstants.MAXIMUM_QUERY_ROWCOUNT +1 ){
           UserDataVO user = null;
           try{
             user = adminsession.findUser(administrator, (String) i.next());
             if(user != null) {
               userlist.add(user);
             }
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
      return endEntityAuthorization(administrator, user.getEndEntityProfileId(),AccessRulesConstants.HISTORY_RIGHTS, false);
    }
    
    public boolean isAuthorizedToEditUser(String username) throws Exception {
        UserDataVO user = adminsession.findUser(administrator, username);
        return endEntityAuthorization(administrator, user.getEndEntityProfileId(),AccessRulesConstants.EDIT_RIGHTS, false);
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
    
    
    public String getUserDataSourceName(int sourceid) throws RemoteException{
      return this.userdatasourcesession.getUserDataSourceName(administrator, sourceid);
    }

    public int getUserDataSourceId(String sourcename){
      return this.userdatasourcesession.getUserDataSourceId(administrator, sourcename);
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
       if(iter.hasNext()) {
         availablecas = ((Integer) iter.next()).toString();  
       }
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
    		ArrayList list = new ArrayList(certs);
        	if (certs.size() < 50) {
        		Collections.sort(list, new CertificateNotBeforeComparator());        		
        	} else {
        		log.debug("User has more than 50 certificates, we will not sort them");
        	}
    		Iterator j = list.iterator();
    		certificates = new CertificateView[list.size()];
    		for(int i=0; i< certificates.length; i++){
    			RevokedInfoView revokedinfo = null;
    			Certificate cert = (Certificate) j.next();
    			CertificateStatus revinfo = certificatesession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
    			if(revinfo != null) {
    				revokedinfo = new RevokedInfoView(revinfo, CertTools.getSerialNumber(cert));
    			}
    			certificates[i] = new CertificateView(cert, revokedinfo, username);
    		}
    	}
    	else{
    		certificates = null;
    	}
    } // loadCertificateView

    public boolean revokeTokenCertificates(String tokensn, String username, int reason) throws RemoteException, NamingException, CreateException,
    		ApprovalException, WaitingForApprovalException, AlreadyRevokedException {
       boolean success = true;
       ApprovalException lastAppException = null;
       WaitingForApprovalException lastWaitException = null;
       AlreadyRevokedException lastRevokedException = null;
       Collection certs = hardtokensession.findCertificatesInHardToken(administrator, tokensn);
       Iterator i = certs.iterator();
       // Extract and revoke collection
       while ( i.hasNext() ) {
    	   Certificate cert = (Certificate)i.next();
           try {
        	   adminsession.revokeCert(administrator, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert), username, reason);
        	// Ignore errors if some were successful 
           } catch (ApprovalException e) {
        	   lastAppException = e;
           } catch (WaitingForApprovalException e) {
        	   lastWaitException = e;
           } catch (AlreadyRevokedException e) {
        	   lastRevokedException = e;
           } catch (AuthorizationDeniedException e) {
        	   success = false;
           } catch (FinderException e) {
        	   success = false;
           }
       }
       if ( lastWaitException != null ) {
    	   throw lastWaitException;
       }
       if ( lastAppException != null ) {
    	   throw lastAppException; 
       }
       if ( lastRevokedException != null ) {
    	   throw lastRevokedException; 
       }
       return success;
    }

    public boolean isAllTokenCertificatesRevoked(String tokensn, String username) throws RemoteException, NamingException, CreateException, AuthorizationDeniedException, FinderException{
      Collection certs = hardtokensession.findCertificatesInHardToken(administrator, tokensn);
      boolean allrevoked = true;
      if(!certs.isEmpty()){
        Iterator j = certs.iterator();
        while(j.hasNext()){
          Certificate cert = (Certificate)j.next();        
          boolean isrevoked = certificatesession.isRevoked(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));          
          if (!isrevoked) {
            allrevoked = false;
          }
        }
      }
      return allrevoked;
    }

    public void loadCACertificates(CertificateView[] cacerts) {
        certificates = cacerts;
    }

    public void loadCertificates(BigInteger serno, String issuerdn) throws RemoteException, NamingException, CreateException, AuthorizationDeniedException, FinderException{
	  try{	
		  authorizationsession.isAuthorizedNoLog(administrator, AccessRulesConstants.CAPREFIX + issuerdn.hashCode());        
		  Certificate cert = certificatesession.findCertificateByIssuerAndSerno(administrator, issuerdn, serno);
		  
		  if(cert != null){
			  RevokedInfoView revokedinfo = null;
			  String username = certificatesession.findUsernameByCertSerno(administrator,serno, CertTools.getIssuerDN(cert));
			  if(this.adminsession.findUser(administrator, username) != null){
				  int endentityprofileid = this.adminsession.findUser(administrator, username).getEndEntityProfileId();
				  this.endEntityAuthorization(administrator,endentityprofileid,AccessRulesConstants.VIEW_RIGHTS,true);
			  }
			  CertificateStatus revinfo = certificatesession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
			  if(revinfo != null) {
				  revokedinfo = new RevokedInfoView(revinfo, CertTools.getSerialNumber(cert));
			  }
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
      return endEntityAuthorization(administrator, profileid, AccessRulesConstants.EDIT_RIGHTS, false);
    }

    public boolean authorizedToViewHistory(int profileid) throws RemoteException{
      return endEntityAuthorization(administrator, profileid, AccessRulesConstants.HISTORY_RIGHTS, false);
    }

    public boolean authorizedToViewHardToken(String username) throws Exception{      
      int profileid = adminsession.findUser(administrator, username).getEndEntityProfileId();
      if(!endEntityAuthorization(administrator, profileid, AccessRulesConstants.HARDTOKEN_RIGHTS, false)){
    	  throw new AuthorizationDeniedException();
      }
      if(!WebConfiguration.getHardTokenDiplaySensitiveInfo()){
    	  return false;
      }
      
      return endEntityAuthorization(administrator, profileid, AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS, false);
    }

    public boolean authorizedToViewHardToken(int profileid) throws Exception{
      return endEntityAuthorization(administrator, profileid, AccessRulesConstants.HARDTOKEN_RIGHTS, false);
    }    

    public boolean authorizedToRevokeCert(String username) throws FinderException, RemoteException, AuthorizationDeniedException{
      boolean returnval=false;
      UserDataVO data = adminsession.findUser(administrator, username);
      if(data == null) {
        return false;
      }
      int profileid = data.getEndEntityProfileId();

      if(informationmemory.getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
       returnval= endEntityAuthorization(administrator, profileid, AccessRulesConstants.REVOKE_RIGHTS, false);
      } else {
       returnval=true;
      }
      return returnval;
    }


    public boolean keyRecoveryPossible(Certificate cert, String username) throws Exception{
      boolean returnval = true;
      
      try{
        authorizationsession.isAuthorizedNoLog(administrator, AccessRulesConstants.REGULAR_KEYRECOVERY);
      }catch(AuthorizationDeniedException ade){
      	returnval = false;
      }
	  
      if(informationmemory.getGlobalConfiguration().getEnableEndEntityProfileLimitations()){
      	UserDataVO data = adminsession.findUser(administrator, username);
      	if(data != null){       	
          int profileid = data.getEndEntityProfileId();
		  returnval = endEntityAuthorization(administrator, profileid, AccessRulesConstants.KEYRECOVERY_RIGHTS, false);		  
      	}else {
          returnval = false;
      	}
      }
      return returnval && keyrecoverysession.existsKeys(administrator, cert) && !keyrecoverysession.isUserMarked(administrator,username);
    }

    public void markForRecovery(String username, Certificate cert) throws Exception{
      boolean authorized = true;
      int endEntityProfileId = adminsession.findUser(administrator, username).getEndEntityProfileId();
      if(informationmemory.getGlobalConfiguration().getEnableEndEntityProfileLimitations()){
        authorized = endEntityAuthorization(administrator, endEntityProfileId, AccessRulesConstants.KEYRECOVERY_RIGHTS, false);
      }

      if(authorized){
    	  adminsession.prepareForKeyRecovery(administrator, username, endEntityProfileId, cert);
      }
    }

    public String[] getCertificateProfileNames(){
        String[] dummy = {""};
        Collection certprofilenames = this.informationmemory.getAuthorizedEndEntityCertificateProfileNames().keySet();
        if(certprofilenames == null) {
            return new String[0];
        }
        return (String[]) certprofilenames.toArray(dummy);
    }

    public int getCertificateProfileId(String certificateprofilename) throws RemoteException{
      return certificatesession.getCertificateProfileId(administrator, certificateprofilename);
    }
    public String getCertificateProfileName(int certificateprofileid) throws RemoteException{
      return this.informationmemory.getCertificateProfileNameProxy().getCertificateProfileName(certificateprofileid);
    }

    public boolean getEndEntityParameter(String parameter){
       if(parameter == null) {
         return false;
       }

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
        if(log) {
           returnval = authorizationsession.isAuthorized(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX+Integer.toString(profileid)+rights) &&
           authorizationsession.isAuthorized(admin, AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
        } else {
           returnval = authorizationsession.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX+Integer.toString(profileid)+rights)&&
           authorizationsession.isAuthorized(admin, AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
        }
      } catch(AuthorizationDeniedException e){}

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
    
    UserDataSourceSession getUserDataSourceSession(){
    	return userdatasourcesession;
    }
    
    public String[] listPrinters(){
    	if(printerNames == null){
    		printerNames = org.ejbca.util.PrinterManager.listPrinters();
    	}
    	
    	return printerNames;
    }

    //
    // Private fields.
    //
    private EndEntityProfileDataHandler    profiles;

    private UserAdminSession adminsession;
    private CertificateStoreSession certificatesession;
    private RaAdminSession raadminsession;
    private AuthorizationSession authorizationsession;
    private HardTokenSession hardtokensession;
    private KeyRecoverySession keyrecoverysession;
    private UserDataSourceSession userdatasourcesession;

    private UsersView                           users;
    private CertificateView[]                  certificates;
    private AddedUserMemory              addedusermemory;
    private Admin                                 administrator;   
    private InformationMemory             informationmemory;
    private boolean initialized=false;
    
    private String[] printerNames = null;
    
    private EndEntityProfile temporateendentityprofile = null;  
}
